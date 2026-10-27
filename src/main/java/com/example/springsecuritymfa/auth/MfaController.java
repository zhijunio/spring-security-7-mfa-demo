package com.example.springsecuritymfa.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class MfaController {
    private final MfaService mfa;

    public MfaController(MfaService mfa) {
        this.mfa = mfa;
    }

    @GetMapping("/csrf")
    Map<String, String> csrf(CsrfToken token) {
        return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }

    @GetMapping("/auth/state")
    Map<String, Object> session(Authentication a) {
        return Map.of(
                "primaryAuthenticated",
                mfa.hasPrimary(a),
                "mfaComplete",
                mfa.complete(a),
                "username",
                mfa.hasPrimary(a) ? a.getName() : "");
    }

    @GetMapping("/me")
    Map<String, String> me(Authentication a) {
        return Map.of("username", a.getName(), "message", "MFA protected resource");
    }

    @GetMapping("/me/security")
    Map<String, String> security(Authentication a) {
        return Map.of("username", a.getName(), "message", "Recent MFA step-up is valid");
    }

    @GetMapping("/mfa/factors")
    Map<String, Object> factors(Authentication a) {
        return Map.of("factors", mfa.factors(a.getName()));
    }

    @DeleteMapping("/mfa/factors/{factorType}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void removeFactor(@PathVariable String factorType, Authentication a) {
        mfa.removeFactor(a.getName(), factorType);
    }

    @PostMapping("/auth/mfa/challenge")
    Map<String, String> challenge(@Valid @RequestBody Challenge input, Authentication a, HttpServletRequest r) {
        return switch (input.factorType) {
            case "EMAIL_OTP" -> { mfa.sendEmail(a.getName()); yield Map.of("status", "Development email code issued; see local log"); }
            case "WALLET_SIGNATURE" -> Map.of("message", mfa.walletChallenge(a.getName(), sessionId(r)));
            case "TOTP", "BIP39_MNEMONIC", "WEBAUTHN" -> Map.of("status", "This factor does not require a separate challenge in this demo");
            default -> throw new IllegalArgumentException("Unsupported factor type");
        };
    }

    @PostMapping("/auth/mfa/verify")
    Map<String, String> verify(
            @Valid @RequestBody Proof input, Authentication a, HttpServletRequest r, HttpServletResponse s) {
        String user = a.getName();
        String authority = switch (input.factorType) {
            case "EMAIL_OTP" -> { mfa.verifyEmail(user, input.proof); yield MfaService.EMAIL_FACTOR; }
            case "TOTP" -> { mfa.verifyTotp(user, input.proof); yield MfaService.TOTP_FACTOR; }
            case "WALLET_SIGNATURE" -> { mfa.verifyWallet(user, input.proof, sessionId(r)); yield MfaService.WALLET_FACTOR; }
            case "BIP39_MNEMONIC" -> { mfa.verifyBip39MfaMnemonic(user, input.proof); yield MfaService.MNEMONIC_FACTOR; }
            case "WEBAUTHN" -> throw new IllegalArgumentException("Use the WebAuthn browser ceremony");
            default -> throw new IllegalArgumentException("Unsupported factor type");
        };
        mfa.verify(a, authority, r, s);
        return Map.of("status", "verified");
    }

    @PostMapping("/mfa/totp/enroll")
    Map<String, String> enrollTotp(Authentication a) {
        String secret = mfa.enrollTotp(a.getName());
        String uri = "otpauth://totp/Local%20MFA:" + URLEncoder.encode(a.getName(), StandardCharsets.UTF_8) + "?secret="
                + secret + "&issuer=Local%20MFA";
        return Map.of("secret", secret, "otpauthUri", uri, "warning", "Demo only; protect this secret in production.");
    }

    @PostMapping("/mfa/totp/confirm")
    Map<String, String> confirmTotp(@Valid @RequestBody Code input, Authentication a) {
        mfa.confirmTotp(a.getName(), input.code);
        return Map.of("status", "TOTP enrolled");
    }

    @PostMapping("/mfa/wallet/enroll")
    Map<String, String> enrollWalletChallenge(@Valid @RequestBody Address input, Authentication a, HttpServletRequest r) {
        return Map.of("message", mfa.walletEnrollChallenge(a.getName(), input.address, sessionId(r)));
    }

    @PostMapping("/mfa/wallet/confirm")
    Map<String, String> confirmWallet(@Valid @RequestBody Signature input, Authentication a, HttpServletRequest r) {
        mfa.enrollWallet(a.getName(), input.signature, sessionId(r));
        return Map.of("status", "wallet enrolled");
    }

    @PostMapping("/mfa/mnemonic/enroll")
    Map<String, String> enrollBip39MfaMnemonic(Authentication a) {
        return Map.of(
                "mnemonic",
                mfa.createBip39MfaMnemonic(a.getName()),
                "warning",
                "Application-generated BIP-39 MFA credential. Reusable for MFA only; not an account recovery code. It can derive wallet keys: never enter it in a wallet. Displayed once.");
    }

    record Code(@NotBlank String code) {}

    record Challenge(@NotBlank String factorType) {}

    record Proof(@NotBlank String factorType, @NotBlank String proof) {}

    record Signature(@NotBlank String signature) {}

    record Address(@NotBlank String address) {}

    private String sessionId(HttpServletRequest request) {
        var session = request.getSession(false);
        if (session == null) throw new IllegalStateException("Authenticated session is required");
        return session.getId();
    }
}
