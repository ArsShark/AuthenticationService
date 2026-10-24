package com.grechanikovars.authenticationservice.integration;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.service.AccessTokenClaims;
import com.grechanikovars.authenticationservice.service.CredentialService;
import com.grechanikovars.authenticationservice.service.RefreshTokenClaims;
import com.grechanikovars.authenticationservice.service.TokenService;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Tests {@code POST /api/auth/login} through the whole stack: the security chain, the controller,
 * the real BCrypt, the real database and the real signed tokens.
 */
class LoginIntegrationTest extends AbstractIntegrationTest {

  private static final String PATH = "/api/auth/login";
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final Duration ACCESS_TTL = Duration.ofMinutes(15);
  private static final Duration REFRESH_TTL = Duration.ofDays(7);

  @Autowired
  private CredentialService credentialService;

  @Autowired
  private TokenService tokenService;

  @Test
  void aRegisteredUserLogsInAndGetsTokensOfThatAccount() throws Exception {
    credentialService.register("Alice@Example.com", PASSWORD, 7L);

    MvcResult result = login("alice@example.com", PASSWORD).andExpectAll(
        status().isOk(),
        header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")),
        jsonPath("$.tokenType").value("Bearer"),
        jsonPath("$.expiresIn").value(900)).andReturn();

    String json = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    AccessTokenClaims access =
        tokenService.parseAccessToken(JsonPath.read(json, "$.accessToken")).orElseThrow();
    RefreshTokenClaims refresh =
        tokenService.parseRefreshToken(JsonPath.read(json, "$.refreshToken")).orElseThrow();
    long accountId = Objects.requireNonNull(jdbcTemplate.queryForObject(
        "SELECT id FROM credentials WHERE login = 'alice@example.com'", Long.class));
    assertAll(
        () -> assertEquals(accountId, access.credentialId()),
        () -> assertEquals(7L, access.userId()),
        () -> assertEquals(Role.USER, access.role()),
        () -> assertEquals("alice@example.com", access.email()),
        () -> assertEquals(START.plus(ACCESS_TTL), access.expiresAt()),
        () -> assertEquals(accountId, refresh.credentialId()),
        () -> assertEquals(1, countTokens()),
        () -> assertEquals(accountId, storedAccountOf(refresh)),
        () -> assertNull(storedTime("revoked_at", refresh)),
        () -> assertEquals(START.plus(REFRESH_TTL), storedTime("expires_at", refresh)));
  }

  @Test
  void theLoginIsStrippedAndItsCaseIsIgnored() throws Exception {
    credentialService.register("alice@example.com", PASSWORD, 7L);

    login("  ALICE@Example.COM ", PASSWORD).andExpect(status().isOk());
  }

  @Test
  void theFirstAdminLogsInWithoutAProfile() throws Exception {
    credentialService.createAdminIfAbsent("admin@example.com", "Adm1n-passw0rd");

    MvcResult result = login("admin@example.com", "Adm1n-passw0rd")
        .andExpect(status().isOk()).andReturn();

    String json = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    AccessTokenClaims access =
        tokenService.parseAccessToken(JsonPath.read(json, "$.accessToken")).orElseThrow();
    assertAll(
        () -> assertEquals(Role.ADMIN, access.role()),
        () -> assertNull(access.userId()),
        () -> assertEquals("admin@example.com", access.email()));
  }

  @Test
  void everyLoginStartsItsOwnSession() throws Exception {
    credentialService.register("alice@example.com", PASSWORD, 7L);

    String first = login("alice@example.com", PASSWORD).andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    String second = login("alice@example.com", PASSWORD).andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

    RefreshTokenClaims firstRefresh =
        tokenService.parseRefreshToken(JsonPath.read(first, "$.refreshToken")).orElseThrow();
    RefreshTokenClaims secondRefresh =
        tokenService.parseRefreshToken(JsonPath.read(second, "$.refreshToken")).orElseThrow();
    assertAll(
        () -> assertNotEquals(firstRefresh.jti(), secondRefresh.jti()),
        () -> assertEquals(2, countTokens()),
        () -> assertEquals(2, countActiveTokens()));
  }

  /** The time of the tokens comes from the application clock. */
  @Test
  void theTokensAreIssuedAtTheTimeOfTheClock() throws Exception {
    credentialService.register("alice@example.com", PASSWORD, 7L);
    Instant later = START.plus(Duration.ofHours(1));
    clock.set(later);

    MvcResult result = login("alice@example.com", PASSWORD)
        .andExpect(status().isOk()).andReturn();

    String json = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    AccessTokenClaims access =
        tokenService.parseAccessToken(JsonPath.read(json, "$.accessToken")).orElseThrow();
    RefreshTokenClaims refresh =
        tokenService.parseRefreshToken(JsonPath.read(json, "$.refreshToken")).orElseThrow();
    assertAll(
        () -> assertEquals(later.plus(ACCESS_TTL), access.expiresAt()),
        () -> assertEquals(later.plus(REFRESH_TTL), storedTime("expires_at", refresh)));
  }

  /**
   * The two failures give the very same answer: the status, the content type and the body. A
   * client cannot tell whether a login exists. Nothing is stored for a failed login.
   */
  @Test
  void aWrongPasswordAndAnUnknownLoginGetTheSameAnswer() throws Exception {
    credentialService.register("alice@example.com", PASSWORD, 7L);

    MvcResult wrongPassword = login("alice@example.com", "wrong-passw0rd")
        .andExpect(status().isUnauthorized()).andReturn();
    MvcResult unknownLogin = login("nobody@example.com", PASSWORD)
        .andExpect(status().isUnauthorized()).andReturn();

    String wrongBody = wrongPassword.getResponse().getContentAsString(StandardCharsets.UTF_8);
    String unknownBody = unknownLogin.getResponse().getContentAsString(StandardCharsets.UTF_8);
    assertAll(
        () -> assertEquals(wrongBody, unknownBody),
        () -> assertEquals("Authentication is required", JsonPath.read(wrongBody, "$.detail")),
        () -> assertTrue(MediaType.APPLICATION_PROBLEM_JSON.isCompatibleWith(
            MediaType.parseMediaType(wrongPassword.getResponse().getContentType()))),
        () -> assertNull(wrongPassword.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE)),
        () -> assertNull(unknownLogin.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE)),
        () -> assertEquals(0, countTokens()));
  }

  /**
   * BCrypt reads only the first 72 bytes, so without the guard the real password followed by
   * anything would log in. The password here has exactly 72 bytes, which registration allows.
   */
  @Test
  void aPasswordThatBcryptWouldCutDoesNotLogIn() throws Exception {
    String longest = "p".repeat(72);
    credentialService.register("alice@example.com", longest, 7L);

    login("alice@example.com", longest).andExpect(status().isOk());
    login("alice@example.com", String.format("%sanything", longest))
        .andExpect(status().isUnauthorized());
    login("alice@example.com", "p".repeat(73)).andExpect(status().isUnauthorized());

    assertEquals(1, countTokens(), "only the first login stored a token");
  }

  @Test
  void aMalformedBodyIsBadRequestAndStoresNothing() throws Exception {
    mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content("{}"))
        .andExpectAll(
            status().isBadRequest(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
            jsonPath("$.errors.length()").value(2));

    assertEquals(0, countTokens());
  }

  /** Only POST is opened by the security rules. */
  @Test
  void getIsUnauthorized() throws Exception {
    mockMvc.perform(get(PATH)).andExpect(status().isUnauthorized());
  }

  private ResultActions login(String login, String password) throws Exception {
    String body = String.format("{\"login\": \"%s\", \"password\": \"%s\"}", login, password);
    return mockMvc.perform(
        post(PATH).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  private int countTokens() {
    return Objects.requireNonNull(
        jdbcTemplate.queryForObject("SELECT count(*) FROM refresh_tokens", Integer.class));
  }

  private int countActiveTokens() {
    return Objects.requireNonNull(jdbcTemplate.queryForObject(
        "SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL", Integer.class));
  }

  private long storedAccountOf(RefreshTokenClaims refresh) {
    return Objects.requireNonNull(jdbcTemplate.queryForObject(
        "SELECT credential_id FROM refresh_tokens WHERE jti = ?", Long.class, refresh.jti()));
  }

  /** Reads one timestamp column of the stored row of a refresh token. */
  private Instant storedTime(String column, RefreshTokenClaims refresh) {
    OffsetDateTime value = jdbcTemplate.queryForObject(
        String.format("SELECT %s FROM refresh_tokens WHERE jti = ?", column),
        OffsetDateTime.class, refresh.jti());
    return value == null ? null : value.toInstant();
  }
}
