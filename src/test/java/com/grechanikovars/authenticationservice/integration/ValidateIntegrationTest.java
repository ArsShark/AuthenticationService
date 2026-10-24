package com.grechanikovars.authenticationservice.integration;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.service.CredentialService;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Tests {@code POST /api/auth/validate} through the whole stack, with tokens that the real login
 * hands out and the movable test clock.
 *
 * <p>Every token that is not valid gets the same answer, so most checks compare the whole body.
 */
class ValidateIntegrationTest extends AbstractIntegrationTest {

  private static final String LOGIN_PATH = "/api/auth/login";
  private static final String VALIDATE_PATH = "/api/auth/validate";
  private static final String LOGIN = "alice@example.com";
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final Duration ACCESS_TTL = Duration.ofMinutes(15);

  /** The only answer for a token that is not valid. */
  private static final String NOT_VALID = "{\"valid\":false}";

  @Autowired
  private CredentialService credentialService;

  @Test
  void aValidAccessTokenIsDescribed() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String accessToken = accessTokenOf(login(LOGIN, PASSWORD));

    MvcResult result = validate(accessToken).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
        header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")),
        jsonPath("$.valid").value(true),
        jsonPath("$.userId").value(7),
        jsonPath("$.role").value("USER"),
        jsonPath("$.email").doesNotExist(),
        jsonPath("$.credentialId").doesNotExist()).andReturn();

    String expiresAt = JsonPath.read(bodyOf(result), "$.expiresAt");
    assertEquals(START.plus(ACCESS_TTL), Instant.parse(expiresAt));
  }

  @Test
  void theFirstAdminHasNoUserId() throws Exception {
    credentialService.createAdminIfAbsent("admin@example.com", "Adm1n-passw0rd");
    String accessToken = accessTokenOf(login("admin@example.com", "Adm1n-passw0rd"));

    validate(accessToken).andExpectAll(
        status().isOk(),
        jsonPath("$.valid").value(true),
        jsonPath("$.role").value("ADMIN"),
        jsonPath("$.userId").doesNotExist());
  }

  /** A refresh token is a valid token of another kind, and it is not an access token. */
  @Test
  void aRefreshTokenIsNotValid() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String refreshToken = refreshTokenOf(login(LOGIN, PASSWORD));

    validate(refreshToken).andExpectAll(
        status().isOk(),
        jsonPath("$.valid").value(false));
  }

  /** The time of the check comes from the application clock, like the time of the issue. */
  @Test
  void theClockDecidesWhenATokenExpires() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String accessToken = accessTokenOf(login(LOGIN, PASSWORD));

    clock.set(START.plus(Duration.ofMinutes(10)));
    validate(accessToken).andExpect(jsonPath("$.valid").value(true));

    clock.set(START.plus(Duration.ofHours(1)));
    validate(accessToken).andExpect(jsonPath("$.valid").value(false));
  }

  @Test
  void aTextThatIsNotATokenIsNotValid() throws Exception {
    validate("not-a-token").andExpect(jsonPath("$.valid").value(false));
    validate("header.payload.signature").andExpect(jsonPath("$.valid").value(false));
  }

  /** Changing the first character of the signature changes its bytes, so the check must fail. */
  @Test
  void aTokenWithAChangedSignatureIsNotValid() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String accessToken = accessTokenOf(login(LOGIN, PASSWORD));

    validate(withChangedSignature(accessToken)).andExpect(jsonPath("$.valid").value(false));
    validate(accessToken).andExpect(jsonPath("$.valid").value(true));
  }

  /**
   * Garbage, a refresh token, a tampered token and an expired token get exactly the same body,
   * so a client cannot tell why a token is not valid.
   */
  @Test
  void everyTokenThatIsNotValidGetsTheSameAnswer() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String json = login(LOGIN, PASSWORD);
    String accessToken = accessTokenOf(json);
    String garbage = bodyOf(validate("not-a-token").andReturn());
    String refresh = bodyOf(validate(refreshTokenOf(json)).andReturn());
    String tampered = bodyOf(validate(withChangedSignature(accessToken)).andReturn());
    clock.set(START.plus(Duration.ofHours(1)));
    String expired = bodyOf(validate(accessToken).andReturn());

    // A HashSet, because Set.of refuses duplicates and the four bodies must be equal.
    assertEquals(Set.of(NOT_VALID), new HashSet<>(List.of(garbage, refresh, tampered, expired)));
  }

  /**
   * The answer comes from the token alone, like the verification in the other services: after
   * the account is deleted, its access token stays valid until it expires.
   */
  @Test
  void aDeletedAccountKeepsAValidTokenUntilItExpires() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String accessToken = accessTokenOf(login(LOGIN, PASSWORD));
    jdbcTemplate.update("DELETE FROM credentials WHERE login = ?", LOGIN);

    validate(accessToken).andExpect(jsonPath("$.valid").value(true));
  }

  @Test
  void aBodyWithoutATokenIsBadRequest() throws Exception {
    MvcResult noField = mockMvc.perform(
        post(VALIDATE_PATH).contentType(MediaType.APPLICATION_JSON).content("{}")).andReturn();
    MvcResult blank = mockMvc.perform(post(VALIDATE_PATH)
        .contentType(MediaType.APPLICATION_JSON).content("{\"token\": \"   \"}")).andReturn();

    int errorCount = JsonPath.read(bodyOf(noField), "$.errors.length()");
    String field = JsonPath.read(bodyOf(noField), "$.errors[0].field");
    assertAll(
        () -> assertEquals(400, noField.getResponse().getStatus()),
        () -> assertEquals(400, blank.getResponse().getStatus()),
        () -> assertEquals(1, errorCount),
        () -> assertEquals("token", field));
  }

  /** Only POST is opened by the security rules. */
  @Test
  void getIsUnauthorized() throws Exception {
    mockMvc.perform(get(VALIDATE_PATH)).andExpect(status().isUnauthorized());
  }

  /** Logs a user in and returns the body of the answer. */
  private String login(String login, String password) throws Exception {
    String body = String.format("{\"login\": \"%s\", \"password\": \"%s\"}", login, password);
    MvcResult result = mockMvc.perform(
        post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isOk()).andReturn();
    return bodyOf(result);
  }

  private ResultActions validate(String token) throws Exception {
    String body = String.format("{\"token\": \"%s\"}", token);
    return mockMvc.perform(
        post(VALIDATE_PATH).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  /** Changes one character in the first position of the signature, the third part of the JWT. */
  private static String withChangedSignature(String token) {
    int signatureStart = token.lastIndexOf('.') + 1;
    char first = token.charAt(signatureStart);
    char changed = first == 'A' ? 'B' : 'A';
    return String.format("%s%s%s", token.substring(0, signatureStart), changed,
        token.substring(signatureStart + 1));
  }

  private static String bodyOf(MvcResult result) throws Exception {
    return result.getResponse().getContentAsString(StandardCharsets.UTF_8);
  }

  private static String accessTokenOf(String json) {
    return JsonPath.read(json, "$.accessToken");
  }

  private static String refreshTokenOf(String json) {
    return JsonPath.read(json, "$.refreshToken");
  }
}
