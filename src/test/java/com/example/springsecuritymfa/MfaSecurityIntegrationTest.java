package com.example.springsecuritymfa;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.springsecuritymfa.auth.MfaService;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class MfaSecurityIntegrationTest {
    @Autowired
    MockMvc mvc;

    @Autowired
    MfaService mfa;

    @Test
    void csrfTokenFromPageMustBeSentAsHeaderForPasswordLogin() throws Exception {
        var csrfResponse =
                mvc.perform(get("/api/csrf")).andExpect(status().isOk()).andReturn();
        String body = csrfResponse.getResponse().getContentAsString();
        String token = body.replaceAll("(?s).*\\\"token\\\":\\\"([^\\\"]+)\\\".*", "$1");
        String headerName = body.replaceAll("(?s).*\\\"headerName\\\":\\\"([^\\\"]+)\\\".*", "$1");
        mvc.perform(post("/login")
                        .session((MockHttpSession) csrfResponse.getRequest().getSession(false))
                        .param("username", "demo")
                        .param("password", "changeit")
                        .header(headerName, token))
                .andExpect(status().isFound());
    }

    @Test
    void primaryLoginCannotReadUserApiButVerifiedMfaCan() throws Exception {
        var login = mvc.perform(
                        post("/login").with(csrf()).param("username", "demo").param("password", "changeit"))
                .andExpect(status().isFound())
                .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);
        mvc.perform(get("/api/me").session(session))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(403));
        mvc.perform(get("/api/me/security").session(session)).andExpect(status().isForbidden());
        mfa.createBip39MfaMnemonic("demo");
        mvc.perform(delete("/api/mfa/factors/BIP39_MNEMONIC").session(session).with(csrf()))
                .andExpect(status().isForbidden());

        var old = System.out;
        var capture = new ByteArrayOutputStream();
        System.setOut(new PrintStream(capture));
        try {
            mfa.sendEmail("demo");
        } finally {
            System.setOut(old);
        }
        String code = capture.toString(StandardCharsets.UTF_8).replaceAll("(?s).*code=(\\d{6}).*", "$1");
        mvc.perform(post("/api/auth/mfa/verify")
                        .session(session)
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"factorType\":\"EMAIL_OTP\",\"proof\":\"" + code + "\"}"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("demo"));
        mvc.perform(get("/api/me/security").session(session)).andExpect(status().isOk());
        mvc.perform(delete("/api/mfa/factors/BIP39_MNEMONIC").session(session).with(csrf()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/mfa/factors").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.factors[?(@.type == 'BIP39_MNEMONIC')]").doesNotExist());
    }

    @Test
    void unauthenticatedFactorManagementIsRejected() throws Exception {
        mvc.perform(get("/api/me/security"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"));
        mvc.perform(post("/api/mfa/totp/enroll").with(csrf())).andExpect(status().isUnauthorized());
    }
}
