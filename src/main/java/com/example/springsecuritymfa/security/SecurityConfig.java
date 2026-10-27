package com.example.springsecuritymfa.security;

import com.example.springsecuritymfa.auth.MfaService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
@EnableMultiFactorAuthentication(authorities = {})
public class SecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService users(PasswordEncoder encoder) {
        return new InMemoryUserDetailsManager(User.withUsername("demo")
                .password(encoder.encode("changeit"))
                .roles("USER")
                .build());
    }

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, MfaService mfa, ProblemSecurityHandler problems)
            throws Exception {
        return http.authorizeHttpRequests(auth -> auth.requestMatchers(
                                "/",
                                "/index.html",
                                "/app.js",
                                "/styles.css",
                                "/error",
                                "/login",
                                "/logout",
                                "/api/csrf",
                                "/api/auth/state",
                                // Public docs are for this local demo only; production must protect or disable them.
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/webauthn/authenticate/options",
                                "/login/webauthn")
                        .permitAll()
                        .requestMatchers("/api/me/security", "/api/mfa/**", "/webauthn/register", "/webauthn/register/**")
                        .access((a, c) -> new org.springframework.security.authorization.AuthorizationDecision(
                                mfa.recent(c.getRequest(), a.get())))
                        .requestMatchers("/api/auth/mfa/**")
                        .access((a, c) -> new org.springframework.security.authorization.AuthorizationDecision(
                                mfa.hasPrimary(a.get())))
                        .anyRequest()
                        .access((a, c) -> new org.springframework.security.authorization.AuthorizationDecision(
                                mfa.complete(a.get()))))
                .exceptionHandling(e -> e.authenticationEntryPoint(problems).accessDeniedHandler(problems))
                .formLogin(f -> f.loginPage("/").loginProcessingUrl("/login").permitAll())
                .webAuthn(w -> w.rpName("MFA Demo")
                        .rpId("localhost")
                        .allowedOrigins("http://localhost:8080")
                        .disableDefaultRegistrationPage(true))
                .logout(Customizer.withDefaults())
                .build();
    }
}
