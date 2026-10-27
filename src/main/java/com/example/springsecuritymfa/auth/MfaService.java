package com.example.springsecuritymfa.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

@Service
public class MfaService {
    static final String VERIFIED_AT = "MFA_VERIFIED_AT";
    static final String VERIFIED_SUBJECT = "MFA_VERIFIED_SUBJECT";
    static final Duration STEP_UP = Duration.ofMinutes(5);
    static final String EMAIL_FACTOR = "FACTOR_EMAIL";
    static final String TOTP_FACTOR = "FACTOR_TOTP";
    static final String WALLET_FACTOR = "FACTOR_WALLET";
    static final String MNEMONIC_FACTOR = "FACTOR_BIP39_MNEMONIC";
    private final Clock clock;
    private final SecurityContextRepository contexts;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, EmailChallenge> emails = new ConcurrentHashMap<>();
    private final Map<String, Totp> totps = new ConcurrentHashMap<>();
    private final Map<String, String> pendingTotps = new ConcurrentHashMap<>();
    private final Map<String, Wallet> wallets = new ConcurrentHashMap<>();
    private final Map<String, WalletChallenge> walletChallenges = new ConcurrentHashMap<>();
    private final Map<String, Bip39MfaCredential> bip39MfaCredentials = new ConcurrentHashMap<>();

    public MfaService(Clock clock, SecurityContextRepository contexts) {
        this.clock = clock;
        this.contexts = contexts;
    }

    public boolean hasPrimary(Authentication a) {
        return a != null
                && a.isAuthenticated()
                && !(a instanceof AnonymousAuthenticationToken)
                && a.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .anyMatch(x -> x.equals(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                                || x.equals(FactorGrantedAuthority.WEBAUTHN_AUTHORITY));
    }

    public boolean complete(Authentication a) {
        return hasPrimary(a)
                && a.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .anyMatch(x -> java.util.Set.of(EMAIL_FACTOR, TOTP_FACTOR, WALLET_FACTOR, MNEMONIC_FACTOR)
                                .contains(x));
    }

    public boolean recent(HttpServletRequest r, Authentication a) {
        var s = r.getSession(false);
        if (s == null || a == null || !complete(a)) return false;
        Object at = s.getAttribute(VERIFIED_AT), subject = s.getAttribute(VERIFIED_SUBJECT);
        return a.getName().equals(subject)
                && at instanceof Instant i
                && !Duration.between(i, clock.instant()).isNegative()
                && Duration.between(i, clock.instant()).compareTo(STEP_UP) < 0;
    }

    public java.util.List<Map<String, String>> factors(String user) {
        var result = new java.util.ArrayList<Map<String, String>>();
        result.add(Map.of("type", "EMAIL_OTP", "status", "available"));
        if (totps.containsKey(user)) result.add(Map.of("type", "TOTP", "status", "active"));
        if (wallets.containsKey(user)) result.add(Map.of("type", "WALLET_SIGNATURE", "status", "active"));
        if (bip39MfaCredentials.containsKey(user)) result.add(Map.of("type", "BIP39_MNEMONIC", "status", "active"));
        return java.util.List.copyOf(result);
    }

    public synchronized void removeFactor(String user, String factorType) {
        boolean removed = switch (factorType) {
            case "TOTP" -> {
                boolean active = totps.remove(user) != null;
                boolean pending = pendingTotps.remove(user) != null;
                yield active || pending;
            }
            case "WALLET_SIGNATURE" -> {
                boolean active = wallets.remove(user) != null;
                boolean pending = walletChallenges.remove(user) != null;
                yield active || pending;
            }
            case "BIP39_MNEMONIC" -> bip39MfaCredentials.remove(user) != null;
            default -> throw new IllegalArgumentException("Unsupported factor type");
        };
        if (!removed) throw new IllegalStateException("Factor is not enrolled");
    }

    public void verify(
            Authentication a,
            String factor,
            HttpServletRequest request,
            HttpServletResponse response) {
        var authorities = new java.util.ArrayList<GrantedAuthority>(a.getAuthorities());
        authorities.add(new SimpleGrantedAuthority(factor));
        var updated = new UsernamePasswordAuthenticationToken(a.getPrincipal(), null, authorities);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(updated);
        SecurityContextHolder.setContext(context);
        request.changeSessionId();
        request.getSession().setAttribute(VERIFIED_AT, clock.instant());
        request.getSession().setAttribute(VERIFIED_SUBJECT, a.getName());
        contexts.saveContext(context, request, response);
    }

    public void sendEmail(String user) {
        String code = "%06d".formatted(random.nextInt(1_000_000));
        emails.put(user, new EmailChallenge(hash(code), clock.instant().plusSeconds(300), 0));
        System.out.printf("[DEVELOPMENT ONLY MFA EMAIL] to=%s@example.test code=%s%n", user, code);
    }

    public void verifyEmail(String user, String code) {
        EmailChallenge c = emails.get(user);
        if (c == null || !clock.instant().isBefore(c.expires) || c.attempts >= 5) {
            emails.remove(user);
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        }
        if (!MessageDigest.isEqual(c.digest, hash(code))) {
            emails.replace(user, c, new EmailChallenge(c.digest, c.expires, c.attempts + 1));
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        }
        if (!emails.remove(user, c)) throw new IllegalArgumentException("Invalid, expired, or locked verification");
    }

    public synchronized String enrollTotp(String user) {
        byte[] b = new byte[20];
        random.nextBytes(b);
        String secret = new Base32().encodeToString(b).replace("=", "");
        pendingTotps.put(user, secret);
        return secret;
    }

    public synchronized void confirmTotp(String user, String code) {
        String secret = pendingTotps.get(user);
        if (secret == null) throw new IllegalArgumentException("Invalid, expired, or locked verification");
        long acceptedStep = matchingTotpStep(secret, code);
        if (acceptedStep < 0) throw new IllegalArgumentException("Invalid, expired, or locked verification");
        totps.put(user, new Totp(secret, true, acceptedStep));
        pendingTotps.remove(user, secret);
    }

    public synchronized void verifyTotp(String user, String code) {
        Totp t = totps.get(user);
        if (t == null || !t.enabled) throw new IllegalArgumentException("Invalid, expired, or locked verification");
        long step = clock.instant().getEpochSecond() / 30;
        long matched = -1;
        for (long i = step - 1; i <= step + 1; i++) if (totp(t.secret, i).equals(code)) matched = Math.max(matched, i);
        if (matched < 0 || matched <= t.lastStep)
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        totps.put(user, new Totp(t.secret, true, matched));
    }

    public synchronized String createBip39MfaMnemonic(String user) {
        byte[] entropy = new byte[16];
        random.nextBytes(entropy);
        String mnemonic = org.web3j.crypto.MnemonicUtils.generateMnemonic(entropy);
        bip39MfaCredentials.put(user, new Bip39MfaCredential(hash(normalize(mnemonic)), 0, null));
        return mnemonic;
    }

    public synchronized void verifyBip39MfaMnemonic(String user, String mnemonic) {
        Bip39MfaCredential r = bip39MfaCredentials.get(user);
        if (r == null) throw new IllegalArgumentException("Invalid, expired, or locked verification");
        Instant now = clock.instant();
        if (r.lockedUntil != null && now.isBefore(r.lockedUntil))
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        int attempts = r.lockedUntil == null ? r.attempts : 0;
        String normalized = normalize(mnemonic);
        if (!org.web3j.crypto.MnemonicUtils.validateMnemonic(normalized)
                || !MessageDigest.isEqual(r.digest, hash(normalized))) {
            int failedAttempts = attempts + 1;
            Instant lockedUntil = failedAttempts >= 5 ? now.plus(Duration.ofMinutes(5)) : null;
            bip39MfaCredentials.replace(user, r, new Bip39MfaCredential(r.digest, failedAttempts, lockedUntil));
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        }
        if (!bip39MfaCredentials.replace(user, r, new Bip39MfaCredential(r.digest, 0, null)))
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
    }

    public synchronized String walletChallenge(String user, String sessionId) {
        Wallet w = wallets.get(user);
        if (w == null) throw new IllegalStateException("Wallet not enrolled");
        return challenge(user, w.address, sessionId);
    }

    public synchronized String walletEnrollChallenge(String user, String address, String sessionId) {
        String normalized = normalizeAddress(address);
        walletChallenges.remove(user);
        return challenge(user, normalized, sessionId);
    }

    private String challenge(String user, String address, String sessionId) {
        if (sessionId == null || sessionId.isBlank()) throw new IllegalStateException("Session is required");
        String nonce = token(24);
        Instant exp = clock.instant().plusSeconds(300);
        String msg = "localhost wants you to sign in with your Ethereum account:\n" + address
                + "\n\nMFA demo wallet verification.\n\nURI: http://localhost:8080\nVersion: 1\nChain ID: 1\nNonce: "
                + nonce + "\nIssued At: " + clock.instant() + "\nExpiration Time: " + exp;
        walletChallenges.put(user, new WalletChallenge(address, msg, exp, sessionId));
        return msg;
    }

    public synchronized void enrollWallet(String user, String signature, String sessionId) {
        WalletChallenge c = requireChallenge(user, sessionId);
        String recovered = recover(c.message, signature);
        if (!recovered.equalsIgnoreCase(c.address) || !walletChallenges.remove(user, c))
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        wallets.put(user, new Wallet(recovered));
    }

    public synchronized void verifyWallet(String user, String signature, String sessionId) {
        WalletChallenge c = requireChallenge(user, sessionId);
        String expected = wallets.containsKey(user) ? wallets.get(user).address : "";
        if (!recover(c.message, signature).equalsIgnoreCase(expected) || !walletChallenges.remove(user, c))
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
    }

    private WalletChallenge requireChallenge(String u, String sessionId) {
        WalletChallenge c = walletChallenges.get(u);
        if (c == null || !clock.instant().isBefore(c.expires)) {
            walletChallenges.remove(u);
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        }
        if (!c.sessionId.equals(sessionId))
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        return c;
    }

    private String recover(String message, String sig) {
        try {
            byte[] b = Numeric.hexStringToByteArray(sig);
            if (b.length != 65) throw new IllegalArgumentException();
            var data = new Sign.SignatureData(
                    new byte[] {b[64]},
                    java.util.Arrays.copyOfRange(b, 0, 32),
                    java.util.Arrays.copyOfRange(b, 32, 64));
            return "0x"
                    + Keys.getAddress(Sign.signedPrefixedMessageToKey(message.getBytes(StandardCharsets.UTF_8), data));
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid, expired, or locked verification");
        }
    }

    private String normalizeAddress(String a) {
        if (a == null || !a.matches("(?i)^0x[0-9a-f]{40}$"))
            throw new IllegalArgumentException("Invalid Ethereum address");
        return "0x" + a.substring(2).toLowerCase(Locale.ROOT);
    }

    private long matchingTotpStep(String secret, String code) {
        long step = clock.instant().getEpochSecond() / 30;
        long matched = -1;
        for (long candidate = step - 1; candidate <= step + 1; candidate++) {
            if (totp(secret, candidate).equals(code)) matched = Math.max(matched, candidate);
        }
        return matched;
    }

    private String totp(String secret, long step) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(new Base32().decode(secret), "HmacSHA1"));
            byte[] h = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
            int o = h[h.length - 1] & 15;
            int n = ((h[o] & 127) << 24) | ((h[o + 1] & 255) << 16) | ((h[o + 2] & 255) << 8) | (h[o + 3] & 255);
            return "%06d".formatted(n % 1_000_000);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] hash(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String normalize(String p) {
        return p == null ? "" : p.strip().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
    }

    private String token(int n) {
        byte[] b = new byte[n];
        random.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    record EmailChallenge(byte[] digest, Instant expires, int attempts) {}

    record Totp(String secret, boolean enabled, long lastStep) {}

    record Wallet(String address) {}

    record WalletChallenge(String address, String message, Instant expires, String sessionId) {}

    record Bip39MfaCredential(byte[] digest, int attempts, Instant lockedUntil) {}
}
