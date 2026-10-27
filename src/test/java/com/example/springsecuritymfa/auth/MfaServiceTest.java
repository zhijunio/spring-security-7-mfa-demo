package com.example.springsecuritymfa.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

class MfaServiceTest {
    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-16T00:00:00Z"));
    private final MfaService service = new MfaService(clock, new HttpSessionSecurityContextRepository());

    @Test
    void emailCodeRejectsWrongReplayAndExpiredProofs() {
        var old = System.out;
        var bytes = new ByteArrayOutputStream();
        System.setOut(new PrintStream(bytes));
        String code;
        try {
            service.sendEmail("demo");
        } finally {
            System.setOut(old);
        }
        code = bytes.toString(StandardCharsets.UTF_8).replaceAll("(?s).*code=(\\d{6}).*", "$1");
        assertThat(code).matches("\\d{6}");
        String wrongCode = code.equals("000000") ? "000001" : "000000";
        assertThatThrownBy(() -> service.verifyEmail("demo", wrongCode)).isInstanceOf(IllegalArgumentException.class);
        service.verifyEmail("demo", code);
        assertThatThrownBy(() -> service.verifyEmail("demo", code)).isInstanceOf(IllegalArgumentException.class);
        var secondBytes = new ByteArrayOutputStream();
        old = System.out;
        System.setOut(new PrintStream(secondBytes));
        try {
            service.sendEmail("demo");
        } finally {
            System.setOut(old);
        }
        String secondCode = secondBytes.toString(StandardCharsets.UTF_8).replaceAll("(?s).*code=(\\d{6}).*", "$1");
        clock.advanceSeconds(301);
        assertThatThrownBy(() -> service.verifyEmail("demo", secondCode)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void bip39MfaMnemonicIsReusableAndTemporarilyLockedAfterRepeatedFailures() {
        String mnemonic = service.createBip39MfaMnemonic("demo");
        assertThat(mnemonic.split(" ")).hasSize(12);
        assertThat(org.web3j.crypto.MnemonicUtils.validateMnemonic(mnemonic)).isTrue();
        service.verifyBip39MfaMnemonic("demo", mnemonic);
        service.verifyBip39MfaMnemonic("demo", mnemonic);
        mnemonic = service.createBip39MfaMnemonic("demo");
        String validMnemonic = mnemonic;
        for (int i = 0; i < 5; i++)
            assertThatThrownBy(() -> service.verifyBip39MfaMnemonic("demo", "wrong phrase"))
                    .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.verifyBip39MfaMnemonic("demo", validMnemonic))
                .isInstanceOf(IllegalArgumentException.class);
        clock.advanceSeconds(301);
        service.verifyBip39MfaMnemonic("demo", validMnemonic);
    }

    @Test
    void enrolledFactorCanBeRemovedAndMissingFactorCannotBeRemovedAgain() {
        service.createBip39MfaMnemonic("demo");
        service.removeFactor("demo", "BIP39_MNEMONIC");
        assertThat(service.factors("demo")).noneMatch(f -> f.get("type").equals("BIP39_MNEMONIC"));
        assertThatThrownBy(() -> service.removeFactor("demo", "BIP39_MNEMONIC"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> service.removeFactor("demo", "EMAIL_OTP"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void walletChallengeCannotBeReplayedAndExpires() {
        Credentials wallet = Credentials.create("1");
        String message = service.walletEnrollChallenge("demo", wallet.getAddress(), "session-a");
        service.enrollWallet("demo", sign(message, wallet), "session-a");
        String login = service.walletChallenge("demo", "session-a");
        String signature = sign(login, wallet);
        assertThatThrownBy(() -> service.verifyWallet("demo", signature, "session-b"))
                .isInstanceOf(IllegalArgumentException.class);
        service.verifyWallet("demo", signature, "session-a");
        assertThatThrownBy(() -> service.verifyWallet("demo", signature, "session-a"))
                .isInstanceOf(IllegalArgumentException.class);
        String expired = service.walletChallenge("demo", "session-a");
        clock.advanceSeconds(301);
        assertThatThrownBy(() -> service.verifyWallet("demo", sign(expired, wallet), "session-a"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void totpCodeCannotBeReplayedAndStepUpMustBeRecentAndSubjectBound() throws Exception {
        String secret = service.enrollTotp("demo");
        String code = currentTotp(secret, clock.instant().getEpochSecond() / 30);
        service.confirmTotp("demo", code);
        assertThatThrownBy(() -> service.verifyTotp("demo", code)).isInstanceOf(IllegalArgumentException.class);
        clock.advanceSeconds(30);
        service.verifyTotp("demo", currentTotp(secret, clock.instant().getEpochSecond() / 30));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(MfaService.VERIFIED_AT, clock.instant());
        request.getSession().setAttribute(MfaService.VERIFIED_SUBJECT, "demo");
        var authentication = new UsernamePasswordAuthenticationToken(
                "demo",
                null,
                List.of(new SimpleGrantedAuthority("FACTOR_TOTP"), new SimpleGrantedAuthority("FACTOR_PASSWORD")));
        assertThat(service.recent(request, authentication)).isTrue();
        assertThat(service.recent(
                        request,
                        new UsernamePasswordAuthenticationToken("other", null, authentication.getAuthorities())))
                .isFalse();
        clock.advanceSeconds(301);
        assertThat(service.recent(request, authentication)).isFalse();
    }

    private static String sign(String message, Credentials credentials) {
        Sign.SignatureData signature =
                Sign.signPrefixedMessage(message.getBytes(StandardCharsets.UTF_8), credentials.getEcKeyPair());
        byte[] result = new byte[65];
        System.arraycopy(signature.getR(), 0, result, 0, 32);
        System.arraycopy(signature.getS(), 0, result, 32, 32);
        System.arraycopy(signature.getV(), 0, result, 64, 1);
        return Numeric.toHexString(result);
    }

    private static String currentTotp(String secret, long step) throws Exception {
        var mac = javax.crypto.Mac.getInstance("HmacSHA1");
        mac.init(new javax.crypto.spec.SecretKeySpec(
                new org.apache.commons.codec.binary.Base32().decode(secret), "HmacSHA1"));
        byte[] hash = mac.doFinal(java.nio.ByteBuffer.allocate(8).putLong(step).array());
        int offset = hash[hash.length - 1] & 15;
        int value = ((hash[offset] & 127) << 24)
                | ((hash[offset + 1] & 255) << 16)
                | ((hash[offset + 2] & 255) << 8)
                | (hash[offset + 3] & 255);
        return "%06d".formatted(value % 1_000_000);
    }

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advanceSeconds(long seconds) {
            now = now.plusSeconds(seconds);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
