package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.security.InternalKeyAuthenticationFilter;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Tests the security chain of the whole application, with the real beans and a real database:
 * that it is applied to every request, that it answers in the format of the service, that it
 * leaks nothing about the internal key or the internal paths, and that the default setup of
 * Spring Boot is switched off.
 *
 * <p>The tests of the web slice ({@code SecurityConfigTest}) prove the rules one by one; these
 * prove that nothing slips through to the database.
 */
class SecurityIntegrationTest extends AbstractIntegrationTest {

  private static final String INTERNAL_PATH = "/internal/credentials";
  private static final String VALID_BODY = """
      {"login": "alice@example.com", "password": "s3cret-passw0rd", "userId": 7}
      """;

  @Value("${app.internal.api-key}")
  private String internalKey;

  @Autowired
  private ApplicationContext context;

  private static MockHttpServletRequestBuilder registration(String path) {
    return post(path).contentType(MediaType.APPLICATION_JSON).content(VALID_BODY);
  }

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

  /**
   * The route that the Gateway opens to the outside must not lead to the endpoint, even for a
   * caller that knows the key: the key means something only under {@code /internal}.
   */
  @Test
  void theRightKeyOutsideTheInternalPathAuthenticatesNobodyAndWritesNothing() throws Exception {
    mockMvc.perform(registration("/api/auth/credentials")
        .header(InternalKeyAuthenticationFilter.HEADER, internalKey))
        .andExpect(status().isUnauthorized());

    assertEquals(0, countAccounts());
  }

  /** The caller must not learn whether a key was missing or wrong, or how close it was. */
  @Test
  void aMissingAndAWrongKeyGetTheSameAnswerAndNothingIsWritten() throws Exception {
    MvcResult missing = mockMvc.perform(registration(INTERNAL_PATH))
        .andExpect(status().isUnauthorized()).andReturn();
    MvcResult wrong = mockMvc.perform(registration(INTERNAL_PATH)
        .header(InternalKeyAuthenticationFilter.HEADER, "wrong-key"))
        .andExpect(status().isUnauthorized()).andReturn();

    String missingBody = missing.getResponse().getContentAsString(StandardCharsets.UTF_8);
    String wrongBody = wrong.getResponse().getContentAsString(StandardCharsets.UTF_8);
    assertAll(
        () -> assertEquals(missingBody, wrongBody),
        () -> assertTrue(missingBody.contains("Authentication is required")),
        () -> assertEquals(0, countAccounts()));
  }

  /** An anonymous caller cannot tell an internal path that exists from one that does not. */
  @Test
  void anInternalPathThatDoesNotExistIsHiddenFromAnonymousCallers() throws Exception {
    mockMvc.perform(get(INTERNAL_PATH)).andExpectAll(
        status().isUnauthorized(),
        jsonPath("$.detail").value("Authentication is required"));
    mockMvc.perform(get("/internal/unknown")).andExpectAll(
        status().isUnauthorized(),
        jsonPath("$.detail").value("Authentication is required"));
  }

  /** The key opens {@code /internal/**} for the caller; what does not exist there is a 404. */
  @Test
  void anInternalPathThatDoesNotExistIsNotFoundForAnInternalCaller() throws Exception {
    mockMvc.perform(get("/internal/unknown")
        .header(InternalKeyAuthenticationFilter.HEADER, internalKey)).andExpectAll(
        status().isNotFound(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(404));
  }

  /** The service is stateless: even a successful call must not start a session. */
  @Test
  void aSuccessfulInternalCallCreatesNoSessionAndNoCookie() throws Exception {
    MvcResult result = mockMvc.perform(registration(INTERNAL_PATH)
        .header(InternalKeyAuthenticationFilter.HEADER, internalKey))
        .andExpect(status().isCreated()).andReturn();

    assertAll(
        () -> assertNull(result.getRequest().getSession(false)),
        () -> assertNull(result.getResponse().getHeader("Set-Cookie")),
        () -> assertEquals(1, countAccounts()));
  }

  /** An authenticated caller without the internal role is refused, and nothing is written. */
  @Test
  void aUserWithoutTheInternalRoleIsForbiddenAndNothingIsWritten() throws Exception {
    mockMvc.perform(registration(INTERNAL_PATH).with(user("alice").roles("USER")))
        .andExpectAll(
            status().isForbidden(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
            jsonPath("$.status").value(403),
            jsonPath("$.detail").value("Access is denied"));

    assertEquals(0, countAccounts());
  }

  /** The default security headers of Spring Security stay on, also for a denied request. */
  @Test
  void theDefaultSecurityHeadersAreWrittenOnADeniedRequest() throws Exception {
    MvcResult result = mockMvc.perform(get("/unknown"))
        .andExpect(status().isUnauthorized()).andReturn();

    String cacheControl = result.getResponse().getHeader("Cache-Control");
    assertAll(
        () -> assertEquals("nosniff", result.getResponse().getHeader("X-Content-Type-Options")),
        () -> assertNotNull(cacheControl),
        () -> assertTrue(cacheControl.contains("no-store")));
  }
}
