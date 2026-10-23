package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.service.CredentialService;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.JWKSet;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Follows one account through the whole life of its tokens, the way a client and the other
 * services use the endpoints one after another: the first admin, the refresh of an admin
 * (a token without a user id), and a user whose old refresh token is used again.
 *
 * <p>Each endpoint has its own tests. These two stories check what only the sequence shows.
 */
class FullFlowIntegrationTest extends AbstractIntegrationTest {

  private static final String LOGIN_PATH = "/api/auth/login";
  private static final String REFRESH_PATH = "/api/auth/refresh";
  private static final String VALIDATE_PATH = "/api/auth/validate";
  private static final String JWKS_PATH = "/.well-known/jwks.json";
  private static final String LOGIN = "alice@example.com";
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final String ADMIN_LOGIN = "admin@example.com";
  private static final String ADMIN_PASSWORD = "Adm1n-passw0rd";

  @Autowired
  private CredentialService credentialService;

  /**
   * The first admin has no profile in the User Service, so its tokens have no user id. That must
   * stay true after a refresh, where the claims are built again from the database, and the
   * refreshed token must verify with the published key like the first one.
   */
  @Test
  void theFirstAdminLogsInIsValidatedRefreshedAndVerifiedWithThePublishedKey() throws Exception {
    credentialService.createAdminIfAbsent(ADMIN_LOGIN, ADMIN_PASSWORD);
    String loginJson = bodyOf(login(ADMIN_LOGIN, ADMIN_PASSWORD).andExpect(status().isOk()));
    validate(accessTokenOf(loginJson)).andExpectAll(
        jsonPath("$.valid").value(true),
        jsonPath("$.role").value("ADMIN"),
        jsonPath("$.userId").doesNotExist());
    Instant refreshedAt = START.plus(Duration.ofMinutes(10));
    clock.set(refreshedAt);

    String refreshJson = bodyOf(
        refresh(refreshTokenOf(loginJson)).andExpect(status().isOk()));

    String refreshedAccess = accessTokenOf(refreshJson);
    MvcResult validation = validate(refreshedAccess).andExpectAll(
        jsonPath("$.valid").value(true),
        jsonPath("$.role").value("ADMIN"),
        jsonPath("$.userId").doesNotExist()).andReturn();
    String expiresAt = JsonPath.read(bodyOf(validation), "$.expiresAt");
    Jwt decoded = publishedKeyDecoder(refreshedAccess).decode(refreshedAccess);
    refresh(refreshTokenOf(refreshJson)).andExpect(status().isOk());
    assertAll(
        () -> assertEquals(refreshedAt.plus(Duration.ofMinutes(15)), Instant.parse(expiresAt)),
        () -> assertEquals("ADMIN", decoded.getClaimAsString("role")),
        () -> assertNull(decoded.getClaim("userId")),
        () -> assertEquals(3, countTokens()),
        () -> assertEquals(1, countActiveTokens()));
  }

  /**
   * A reuse ends every refresh token of the account, but not the account: the user logs in
   * again and gets a working session. An access token that was issued before stays valid until
   * it expires, because it is checked without the database; the revocation is about refresh
   * tokens only.
   */
  @Test
  void afterAReuseTheUserLogsInAgainAndTheOldAccessTokenLivesUntilItExpires() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String firstJson = bodyOf(login(LOGIN, PASSWORD).andExpect(status().isOk()));
    String usedRefreshToken = refreshTokenOf(firstJson);
    String newerJson = bodyOf(refresh(usedRefreshToken).andExpect(status().isOk()));

    refresh(usedRefreshToken).andExpect(status().isUnauthorized());
    refresh(refreshTokenOf(newerJson)).andExpect(status().isUnauthorized());

    validate(accessTokenOf(firstJson)).andExpect(jsonPath("$.valid").value(true));
    int activeAfterReuse = countActiveTokens();
    String againJson = bodyOf(login(LOGIN, PASSWORD).andExpect(status().isOk()));
    refresh(refreshTokenOf(againJson)).andExpect(status().isOk());
    assertAll(
        () -> assertEquals(0, activeAfterReuse),
        () -> assertEquals(4, countTokens()),
        () -> assertEquals(1, countActiveTokens()));
  }

  /** What a client does: find the key by the {@code kid} of the token and verify its signature. */
  private NimbusJwtDecoder publishedKeyDecoder(String token) throws Exception {
    MvcResult keys = mockMvc.perform(get(JWKS_PATH)).andExpect(status().isOk()).andReturn();
    String kid = JsonPath.read(decodePart(token, 0), "$.kid");
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(
        JWKSet.parse(bodyOf(keys)).getKeyByKeyId(kid).toRSAKey().toRSAPublicKey()).build();
    // Only the signature is the point; the clock of the test is far from the real one.
    decoder.setJwtValidator(jwt -> OAuth2TokenValidatorResult.success());
    return decoder;
  }

  private ResultActions login(String login, String password) throws Exception {
    String body = String.format("{\"login\": \"%s\", \"password\": \"%s\"}", login, password);
    return mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  private ResultActions refresh(String token) throws Exception {
    String body = String.format("{\"refreshToken\": \"%s\"}", token);
    return mockMvc.perform(
        post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  private ResultActions validate(String token) throws Exception {
    String body = String.format("{\"token\": \"%s\"}", token);
    return mockMvc.perform(
        post(VALIDATE_PATH).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  private static String bodyOf(ResultActions actions) throws Exception {
    return bodyOf(actions.andReturn());
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

  /** Decodes one of the three parts of a compact JWT: 0 is the header, 1 the payload. */
  private static String decodePart(String token, int index) {
    return new String(Base64.getUrlDecoder().decode(token.split("\\.")[index]),
        StandardCharsets.UTF_8);
  }

  private int countTokens() {
    return Objects.requireNonNull(
        jdbcTemplate.queryForObject("SELECT count(*) FROM refresh_tokens", Integer.class));
  }

  private int countActiveTokens() {
    return Objects.requireNonNull(jdbcTemplate.queryForObject(
        "SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL", Integer.class));
  }
}
