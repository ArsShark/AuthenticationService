package com.grechanikovars.authenticationservice.controller;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.config.SecurityConfig;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.exception.InvalidCredentialsException;
import com.grechanikovars.authenticationservice.exception.InvalidRefreshTokenException;
import com.grechanikovars.authenticationservice.service.AccessTokenClaims;
import com.grechanikovars.authenticationservice.service.AuthService;
import com.grechanikovars.authenticationservice.service.IssuedToken;
import com.grechanikovars.authenticationservice.service.TokenPair;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Tests the HTTP contract of {@link AuthController}: the security chain, the controller, the
 * validation and the error handler work together; the service is a mock.
 */
@WebMvcTest(controllers = AuthController.class,
    properties = "app.internal.api-key=test-internal-key",
    excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class)
@Import(SecurityConfig.class)
class AuthControllerTest {

  private static final String PATH = "/api/auth/login";
  private static final String REFRESH_PATH = "/api/auth/refresh";
  private static final String REFRESH_TOKEN = "old-refresh-token";
  private static final String VALIDATE_PATH = "/api/auth/validate";
  private static final String ACCESS_TOKEN = "some-access-token";
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final Instant NOW = Instant.parse("2026-10-19T10:00:00Z");

  private static final String VALID_BODY = """
      {"login": "Alice@Example.com", "password": "s3cret-passw0rd"}
      """;

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private AuthService authService;

  /** The login is open to everybody: the request carries no key and no token. */
  @Test
  void loginReturnsTheTokensAndIsNeverCached() throws Exception {
    when(authService.login("Alice@Example.com", PASSWORD)).thenReturn(new TokenPair(
        new IssuedToken("access-token-value", UUID.randomUUID(), NOW,
            NOW.plus(Duration.ofMinutes(15))),
        new IssuedToken("refresh-token-value", UUID.randomUUID(), NOW,
            NOW.plus(Duration.ofDays(7)))));

    mockMvc.perform(jsonPost(VALID_BODY)).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
        header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")),
        jsonPath("$.accessToken").value("access-token-value"),
        jsonPath("$.refreshToken").value("refresh-token-value"),
        jsonPath("$.tokenType").value("Bearer"),
        jsonPath("$.expiresIn").value(900));

    verify(authService).login("Alice@Example.com", PASSWORD);
  }

  @Test
  void missingFieldsAreBadRequestAndTheServiceIsNotCalled() throws Exception {
    mockMvc.perform(jsonPost("{}")).andExpectAll(
        status().isBadRequest(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.errors.length()").value(2),
        jsonPath("$.errors[0].field").value("login"),
        jsonPath("$.errors[1].field").value("password"));

    verifyNoInteractions(authService);
  }

  @Test
  void aRejectedValueIsNeverRepeatedInTheAnswer() throws Exception {
    String tooLong = "p".repeat(1025);
    String body = String.format("{\"login\": \"alice@example.com\", \"password\": \"%s\"}",
        tooLong);

    MvcResult result = mockMvc.perform(jsonPost(body))
        .andExpectAll(
            status().isBadRequest(),
            jsonPath("$.errors.length()").value(1),
            jsonPath("$.errors[0].field").value("password"))
        .andReturn();

    assertFalse(result.getResponse().getContentAsString(StandardCharsets.UTF_8)
        .contains(tooLong));
    verifyNoInteractions(authService);
  }

  @Test
  void malformedJsonIsBadRequest() throws Exception {
    mockMvc.perform(jsonPost("{not json")).andExpectAll(
        status().isBadRequest(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    verifyNoInteractions(authService);
  }

  /** The detail is the constant text of every 401, so it says nothing about the cause. */
  @Test
  void failedLoginIsUnauthorizedWithTheConstantDetail() throws Exception {
    when(authService.login("Alice@Example.com", PASSWORD))
        .thenThrow(new InvalidCredentialsException());

    MvcResult result = mockMvc.perform(jsonPost(VALID_BODY))
        .andExpectAll(
            status().isUnauthorized(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
            header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE),
            jsonPath("$.status").value(401),
            jsonPath("$.detail").value("Authentication is required"))
        .andReturn();

    String response = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    assertAll(
        () -> assertFalse(response.contains(InvalidCredentialsException.MESSAGE)),
        () -> assertFalse(response.contains("Alice@Example.com")),
        () -> assertFalse(response.contains(PASSWORD)));
  }

  @Test
  void unexpectedErrorIsInternalServerErrorWithoutDetails() throws Exception {
    when(authService.login("Alice@Example.com", PASSWORD))
        .thenThrow(new IllegalStateException("secret internal detail"));

    MvcResult result = mockMvc.perform(jsonPost(VALID_BODY))
        .andExpectAll(
            status().isInternalServerError(),
            jsonPath("$.detail").value("An unexpected error occurred"))
        .andReturn();

    assertFalse(result.getResponse().getContentAsString(StandardCharsets.UTF_8)
        .contains("secret internal detail"));
  }

  /** Only POST is opened, so another method on the same path is closed, not "not allowed". */
  @Test
  void getIsUnauthorizedBecauseOnlyPostIsOpen() throws Exception {
    mockMvc.perform(get(PATH)).andExpect(status().isUnauthorized());

    verifyNoInteractions(authService);
  }

  /** The refresh is open to everybody too: the caller has no valid access token yet. */
  @Test
  void refreshReturnsTheNewTokensAndIsNeverCached() throws Exception {
    when(authService.refresh(REFRESH_TOKEN)).thenReturn(new TokenPair(
        new IssuedToken("new-access-token", UUID.randomUUID(), NOW,
            NOW.plus(Duration.ofMinutes(15))),
        new IssuedToken("new-refresh-token", UUID.randomUUID(), NOW,
            NOW.plus(Duration.ofDays(7)))));

    mockMvc.perform(refreshPost(refreshBody(REFRESH_TOKEN))).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
        header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")),
        jsonPath("$.accessToken").value("new-access-token"),
        jsonPath("$.refreshToken").value("new-refresh-token"),
        jsonPath("$.tokenType").value("Bearer"),
        jsonPath("$.expiresIn").value(900));

    verify(authService).refresh(REFRESH_TOKEN);
  }

  @Test
  void refreshWithoutATokenIsBadRequestAndTheServiceIsNotCalled() throws Exception {
    mockMvc.perform(refreshPost("{}")).andExpectAll(
        status().isBadRequest(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.errors.length()").value(1),
        jsonPath("$.errors[0].field").value("refreshToken"));

    verifyNoInteractions(authService);
  }

  @Test
  void aRejectedRefreshTokenIsNeverRepeatedInTheAnswer() throws Exception {
    String tooLong = "t".repeat(4097);

    MvcResult result = mockMvc.perform(refreshPost(refreshBody(tooLong)))
        .andExpectAll(
            status().isBadRequest(),
            jsonPath("$.errors.length()").value(1),
            jsonPath("$.errors[0].field").value("refreshToken"))
        .andReturn();

    assertFalse(result.getResponse().getContentAsString(StandardCharsets.UTF_8)
        .contains(tooLong));
    verifyNoInteractions(authService);
  }

  @Test
  void aRefusedRefreshIsUnauthorizedWithTheConstantDetail() throws Exception {
    when(authService.refresh(REFRESH_TOKEN)).thenThrow(new InvalidRefreshTokenException());

    MvcResult result = mockMvc.perform(refreshPost(refreshBody(REFRESH_TOKEN)))
        .andExpectAll(
            status().isUnauthorized(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
            header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE),
            jsonPath("$.status").value(401),
            jsonPath("$.detail").value("Authentication is required"))
        .andReturn();

    String response = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    assertAll(
        () -> assertFalse(response.contains(InvalidRefreshTokenException.MESSAGE)),
        () -> assertFalse(response.contains(REFRESH_TOKEN)));
  }

  @Test
  void getOnTheRefreshPathIsUnauthorizedBecauseOnlyPostIsOpen() throws Exception {
    mockMvc.perform(get(REFRESH_PATH)).andExpect(status().isUnauthorized());

    verifyNoInteractions(authService);
  }

  /** The validation is open to everybody too: it only tells what the caller's own token says. */
  @Test
  void validateTellsWhoAValidTokenBelongsTo() throws Exception {
    when(authService.validate(ACCESS_TOKEN)).thenReturn(Optional.of(new AccessTokenClaims(
        42L, 7L, Role.USER, "alice@example.com", NOW.plus(Duration.ofMinutes(15)))));

    mockMvc.perform(validatePost(validateBody(ACCESS_TOKEN))).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
        header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")),
        jsonPath("$.valid").value(true),
        jsonPath("$.userId").value(7),
        jsonPath("$.role").value("USER"),
        jsonPath("$.expiresAt").value(NOW.plus(Duration.ofMinutes(15)).toString()),
        jsonPath("$.email").doesNotExist(),
        jsonPath("$.credentialId").doesNotExist());

    verify(authService).validate(ACCESS_TOKEN);
  }

  @Test
  void anAdminWithoutAProfileHasNoUserIdInTheAnswer() throws Exception {
    when(authService.validate(ACCESS_TOKEN)).thenReturn(Optional.of(new AccessTokenClaims(
        42L, null, Role.ADMIN, "admin@example.com", NOW.plus(Duration.ofMinutes(15)))));

    mockMvc.perform(validatePost(validateBody(ACCESS_TOKEN))).andExpectAll(
        status().isOk(),
        jsonPath("$.valid").value(true),
        jsonPath("$.role").value("ADMIN"),
        jsonPath("$.userId").doesNotExist());
  }

  /** A token that is not valid is an answer, not an error, and the answer has no reason. */
  @Test
  void aTokenThatIsNotValidGetsOnlyValidFalse() throws Exception {
    when(authService.validate(ACCESS_TOKEN)).thenReturn(Optional.empty());

    mockMvc.perform(validatePost(validateBody(ACCESS_TOKEN))).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
        content().string("{\"valid\":false}"));
  }

  @Test
  void validateWithoutATokenIsBadRequestAndTheServiceIsNotCalled() throws Exception {
    mockMvc.perform(validatePost("{}")).andExpectAll(
        status().isBadRequest(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.errors.length()").value(1),
        jsonPath("$.errors[0].field").value("token"));

    verifyNoInteractions(authService);
  }

  @Test
  void getOnTheValidatePathIsUnauthorizedBecauseOnlyPostIsOpen() throws Exception {
    mockMvc.perform(get(VALIDATE_PATH)).andExpect(status().isUnauthorized());

    verifyNoInteractions(authService);
  }

  private static MockHttpServletRequestBuilder validatePost(String body) {
    return post(VALIDATE_PATH).contentType(MediaType.APPLICATION_JSON).content(body);
  }

  private static String validateBody(String token) {
    return String.format("{\"token\": \"%s\"}", token);
  }

  private static MockHttpServletRequestBuilder jsonPost(String body) {
    return post(PATH).contentType(MediaType.APPLICATION_JSON).content(body);
  }

  private static MockHttpServletRequestBuilder refreshPost(String body) {
    return post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON).content(body);
  }

  private static String refreshBody(String token) {
    return String.format("{\"refreshToken\": \"%s\"}", token);
  }
}
