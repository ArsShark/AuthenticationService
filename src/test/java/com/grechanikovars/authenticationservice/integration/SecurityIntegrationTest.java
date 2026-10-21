package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Tests the security chain of the whole application: that it is applied to every request, that
 * it answers in the format of the service, and that the default setup of Spring Boot is
 * switched off.
 */
class SecurityIntegrationTest extends AbstractIntegrationTest {

  @Autowired
  private ApplicationContext context;

  /**
   * Spring Boot would create an in-memory user with a random password and print the password to
   * the log; the exclusion in the application class must prevent that.
   */
  @Test
  void noDefaultUserDetailsServiceExists() {
    assertEquals(0, context.getBeanNamesForType(UserDetailsService.class).length);
  }

  /** Without the chain this would be a 404 from Spring MVC. */
  @Test
  void anonymousGetToAnUnknownPathIsUnauthorized() throws Exception {
    mockMvc.perform(get("/unknown")).andExpectAll(
        status().isUnauthorized(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(401),
        jsonPath("$.detail").value("Authentication is required"));
  }

  /** Without the chain this would be a 405, because the static resource handler answers. */
  @Test
  void anonymousPostToAnUnknownPathIsUnauthorized() throws Exception {
    mockMvc.perform(post("/unknown")).andExpectAll(
        status().isUnauthorized(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(401));
  }

  /** The error page is reachable only by the container's ERROR dispatch, not by a client. */
  @Test
  void aDirectRequestToTheErrorPageIsUnauthorized() throws Exception {
    mockMvc.perform(get("/error")).andExpect(status().isUnauthorized());
  }
}
