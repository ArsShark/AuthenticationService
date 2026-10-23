package com.grechanikovars.authenticationservice.controller;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.TestKeys;
import com.grechanikovars.authenticationservice.config.SecurityConfig;
import com.grechanikovars.authenticationservice.security.JwksDocument;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Tests the HTTP contract of {@link JwksController}: the security chain and the controller work
 * together, and the document is the real one, built from a test key.
 */
@WebMvcTest(controllers = JwksController.class,
    properties = "app.internal.api-key=test-internal-key",
    excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class)
@Import({SecurityConfig.class, JwksControllerTest.TestDocument.class})
class JwksControllerTest {

  private static final String PATH = "/.well-known/jwks.json";

  @Autowired
  private MockMvc mockMvc;

  /** Supplies the real document instead of a mock, so the JSON is the one that is published. */
  @TestConfiguration
  static class TestDocument {

    @Bean
    JwksDocument jwksDocument() {
      return JwksDocument.from(TestKeys.jwtKeys());
    }
  }

  /** The key is public: the request carries neither a key nor a token. */
  @Test
  void returnsTheKeySetToAnybodyAndLetsClientsCacheItForFiveMinutes() throws Exception {
    mockMvc.perform(get(PATH)).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
        header().string(HttpHeaders.CACHE_CONTROL,
            allOf(containsString("max-age=300"), containsString("public"))),
        jsonPath("$.keys.length()").value(1),
        jsonPath("$.keys[0].kid").value(TestKeys.jwtKeys().keyId()),
        jsonPath("$.keys[0].kty").value("RSA"),
        jsonPath("$.keys[0].use").value("sig"),
        jsonPath("$.keys[0].alg").value("RS256"),
        jsonPath("$.keys[0].n").exists(),
        jsonPath("$.keys[0].e").value("AQAB"),
        jsonPath("$.keys[0].d").doesNotExist());
  }

  @Test
  void answersAClientThatAsksOnlyForJson() throws Exception {
    mockMvc.perform(get(PATH).accept(MediaType.APPLICATION_JSON)).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
  }

  /** Only GET is opened, so another method on the same path is closed. */
  @Test
  void postIsUnauthorizedBecauseOnlyGetIsOpen() throws Exception {
    mockMvc.perform(post(PATH)).andExpect(status().isUnauthorized());
  }
}
