package com.grechanikovars.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.controller.CredentialController;
import com.grechanikovars.authenticationservice.service.CredentialService;
import jakarta.servlet.DispatcherType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Tests {@link SecurityConfig} in a web slice with the real exception handler: the closed chain,
 * the format of its 401 and 403, and the stateless setup. The controller only gives the slice
 * something to load; none of these tests reaches it.
 *
 * <p>The internal key is set only because a web slice picks up every {@code WebMvcConfigurer}
 * by type, even without {@code @Import}, and the service refuses to start without a key.
 */
@WebMvcTest(controllers = CredentialController.class,
    properties = "app.internal.api-key=test-internal-key",
    excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class)
@Import(SecurityConfig.class)
class SecurityConfigTest {

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private CredentialService credentialService;

  @Test
  void anonymousRequestToAnUnknownPathIsAnUnauthorizedProblem() throws Exception {
    mockMvc.perform(get("/unknown")).andExpectAll(
        status().isUnauthorized(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(401),
        jsonPath("$.detail").value("Authentication is required"),
        header().doesNotExist("WWW-Authenticate"));
  }

  @Test
  void authenticatedUserOnAnUnknownPathIsAForbiddenProblem() throws Exception {
    mockMvc.perform(get("/unknown").with(user("alice").roles("USER"))).andExpectAll(
        status().isForbidden(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(403),
        jsonPath("$.detail").value("Access is denied"));
  }

  /** A default chain would save the denied request in a session and set a cookie. */
  @Test
  void aDeniedRequestCreatesNoSessionAndNoCookie() throws Exception {
    MvcResult result = mockMvc.perform(get("/unknown")).andReturn();

    assertAll(
        () -> assertNull(result.getRequest().getSession(false)),
        () -> assertNull(result.getResponse().getHeader("Set-Cookie")));
  }

  /**
   * The container forwards a failed request to the error page with the ERROR dispatch type; that
   * forward must not be denied again. Here Security lets it pass, so Spring MVC answers and
   * finds no handler: 404 instead of the 401 that a REQUEST dispatch gets.
   */
  @Test
  void anErrorDispatchIsNotDeniedBySecurity() throws Exception {
    mockMvc.perform(get("/unknown").with(request -> {
      request.setDispatcherType(DispatcherType.ERROR);
      return request;
    })).andExpect(status().isNotFound());
  }
}
