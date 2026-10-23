package com.grechanikovars.authenticationservice.integration;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Tests {@code POST /api/auth/refresh} through the whole stack, next to the login that hands out
 * the first token: the security chain, the controller, the real database and real signed
 * tokens, with the movable test clock.
 *
 * <p>Every answer is checked, and so is the table of refresh tokens after it, read with plain
 * SQL on another connection: a revocation that was rolled back would show up as a failure.
 */
class RefreshIntegrationTest extends AbstractIntegrationTest {

  private static final String LOGIN_PATH = "/api/auth/login";
  private static final String REFRESH_PATH = "/api/auth/refresh";
  private static final String LOGIN = "alice@example.com";
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final Duration ACCESS_TTL = Duration.ofMinutes(15);
  private static final Duration REFRESH_TTL = Duration.ofDays(7);
  private static final int PARALLEL_REFRESHES = 8;

  @Autowired
  private CredentialService credentialService;

  @Autowired
  private TokenService tokenService;

  @Test
  void aRefreshGivesANewPairAndRevokesTheUsedToken() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String first = login();
    RefreshTokenClaims firstClaims = refreshClaims(first);
    Instant later = START.plus(Duration.ofMinutes(5));
    clock.set(later);

    MvcResult result = refresh(refreshTokenOf(first)).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
        header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")),
        jsonPath("$.tokenType").value("Bearer"),
        jsonPath("$.expiresIn").value(900)).andReturn();

    String json = bodyOf(result);
    AccessTokenClaims access = tokenService.parseAccessToken(accessTokenOf(json)).orElseThrow();
    RefreshTokenClaims second = refreshClaims(json);
    assertAll(
        () -> assertEquals(7L, access.userId()),
        () -> assertEquals(Role.USER, access.role()),
        () -> assertEquals(LOGIN, access.email()),
        () -> assertEquals(later.plus(ACCESS_TTL), access.expiresAt()),
        () -> assertNotEquals(firstClaims.jti(), second.jti()),
        () -> assertEquals(later, storedTime("revoked_at", firstClaims.jti())),
        () -> assertNull(storedTime("revoked_at", second.jti())),
        () -> assertEquals(later.plus(REFRESH_TTL), storedTime("expires_at", second.jti())),
        () -> assertEquals(2, countTokens()),
        () -> assertEquals(1, countActiveTokens()));
  }

  /** Each refresh returns a token that the next refresh accepts. */
  @Test
  void theNewRefreshTokenCanBeUsedAgain() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String current = refreshTokenOf(login());

    for (int i = 0; i < 3; i++) {
      current = refreshTokenOf(bodyOf(refresh(current).andExpect(status().isOk()).andReturn()));
    }

    assertAll(
        () -> assertEquals(4, countTokens()),
        () -> assertEquals(1, countActiveTokens()));
  }

  /**
   * The whole point of rotation: a token that was already used is a sign of a copy, so the
   * refusal also ends the session of whoever holds the newer token.
   */
  @Test
  void reusingATokenEndsTheSessionEvenForTheNewToken() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String used = refreshTokenOf(login());
    String newer = refreshTokenOf(bodyOf(refresh(used).andExpect(status().isOk()).andReturn()));

    refresh(used).andExpect(status().isUnauthorized());
    refresh(newer).andExpect(status().isUnauthorized());

    assertAll(
        () -> assertEquals(0, countActiveTokens()),
        () -> assertEquals(2, countTokens()));
  }

  /** The refusal of a used token revokes every token of the account, on every device. */
  @Test
  void reuseEndsEverySessionOfTheAccount() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String phone = refreshTokenOf(login());
    String laptop = refreshTokenOf(login());
    refresh(phone).andExpect(status().isOk());

    refresh(phone).andExpect(status().isUnauthorized());
    refresh(laptop).andExpect(status().isUnauthorized());

    assertEquals(0, countActiveTokens());
  }

  @Test
  void anAccessTokenIsNotAcceptedAsARefreshToken() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String json = login();

    refresh(accessTokenOf(json)).andExpect(status().isUnauthorized());

    assertEquals(1, countActiveTokens(), "nothing was revoked");
    refresh(refreshTokenOf(json)).andExpect(status().isOk());
  }

  @Test
  void aTextThatIsNotATokenIsRefusedAndRevokesNothing() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    login();

    refresh("not-a-token").andExpect(status().isUnauthorized());
    refresh("header.payload.signature").andExpect(status().isUnauthorized());

    assertEquals(1, countActiveTokens());
  }

  /** An expired token is not a reuse: it is refused and nothing else is touched. */
  @Test
  void anExpiredRefreshTokenIsRefusedAndNotRevoked() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String json = login();
    RefreshTokenClaims claims = refreshClaims(json);
    clock.set(START.plus(REFRESH_TTL).plus(Duration.ofDays(1)));

    refresh(refreshTokenOf(json)).andExpect(status().isUnauthorized());

    assertAll(
        () -> assertNull(storedTime("revoked_at", claims.jti())),
        () -> assertEquals(1, countActiveTokens()));
  }

  @Test
  void aTokenOfADeletedAccountIsRefused() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String json = login();
    jdbcTemplate.update("DELETE FROM credentials WHERE login = ?", LOGIN);

    refresh(refreshTokenOf(json)).andExpect(status().isUnauthorized());

    assertEquals(0, countTokens());
  }

  /** A change of the role in the database acts at the next refresh, not before. */
  @Test
  void aRefreshReadsTheRoleFromTheDatabase() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String json = login();
    jdbcTemplate.update("UPDATE credentials SET role = 'ADMIN' WHERE login = ?", LOGIN);

    MvcResult result = refresh(refreshTokenOf(json)).andExpect(status().isOk()).andReturn();

    AccessTokenClaims before = tokenService.parseAccessToken(accessTokenOf(json)).orElseThrow();
    AccessTokenClaims after =
        tokenService.parseAccessToken(accessTokenOf(bodyOf(result))).orElseThrow();
    assertAll(
        () -> assertEquals(Role.USER, before.role()),
        () -> assertEquals(Role.ADMIN, after.role()));
  }

  /**
   * Garbage, an access token and a used token get the very same answer, so a client cannot tell
   * which check failed.
   */
  @Test
  void everyRefusalGetsTheSameAnswer() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String json = login();
    String used = refreshTokenOf(json);
    refresh(used).andExpect(status().isOk());

    String garbage = refusalBody(refresh("not-a-token"));
    String accessToken = refusalBody(refresh(accessTokenOf(json)));
    String reuse = refusalBody(refresh(used));

    assertAll(
        () -> assertEquals(garbage, accessToken),
        () -> assertEquals(garbage, reuse),
        () -> assertEquals("Authentication is required", JsonPath.read(garbage, "$.detail")));
  }

  @Test
  void aMalformedBodyIsBadRequestAndRevokesNothing() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    login();

    mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON).content("{}"))
        .andExpectAll(
            status().isBadRequest(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
            jsonPath("$.errors.length()").value(1));

    assertEquals(1, countActiveTokens());
  }

  /** Only POST is opened by the security rules. */
  @Test
  void getIsUnauthorized() throws Exception {
    mockMvc.perform(get(REFRESH_PATH)).andExpect(status().isUnauthorized());
  }

  /**
   * Eight HTTP requests use one refresh token at the same moment. Exactly one gets a pair; the
   * other seven get the same 401, and exactly one new row is stored. The test does not check
   * that the new token still works: the losers revoke every valid token of the account,
   * including the new one.
   */
  @RepeatedTest(5)
  void parallelRefreshesWithOneTokenGiveExactlyOneSuccess() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String token = refreshTokenOf(login());

    List<Answer> answers = refreshInParallel(token);

    long succeeded = answers.stream().filter(answer -> answer.status() == 200).count();
    long refused = answers.stream().filter(answer -> answer.status() == 401).count();
    Set<String> refusalBodies = answers.stream()
        .filter(answer -> answer.status() == 401)
        .map(Answer::body)
        .collect(Collectors.toSet());
    assertAll(
        () -> assertEquals(PARALLEL_REFRESHES, answers.size()),
        () -> assertEquals(1L, succeeded),
        () -> assertEquals(PARALLEL_REFRESHES - 1L, refused),
        () -> assertEquals(1, refusalBodies.size(), "every refusal has the same body"),
        () -> assertEquals(2, countTokens()));
  }

  /** The status and the body of one answer. */
  private record Answer(int status, String body) {
  }

  /**
   * Sends {@value #PARALLEL_REFRESHES} refreshes at the same moment: a barrier releases all
   * threads together. An exception in a thread fails the test, because {@code get()} rethrows it.
   */
  private List<Answer> refreshInParallel(String token) throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(PARALLEL_REFRESHES);
    CyclicBarrier barrier = new CyclicBarrier(PARALLEL_REFRESHES);
    try {
      List<Callable<Answer>> tasks = IntStream.range(0, PARALLEL_REFRESHES)
          .<Callable<Answer>>mapToObj(i -> () -> {
            barrier.await();
            MvcResult result = refresh(token).andReturn();
            return new Answer(result.getResponse().getStatus(), bodyOf(result));
          })
          .toList();
      List<Answer> answers = new ArrayList<>();
      for (Future<Answer> future : executor.invokeAll(tasks)) {
        answers.add(future.get());
      }
      return answers;
    } finally {
      executor.shutdownNow();
    }
  }

  /** Logs the test user in and returns the body of the answer. */
  private String login() throws Exception {
    String body = String.format("{\"login\": \"%s\", \"password\": \"%s\"}", LOGIN, PASSWORD);
    MvcResult result = mockMvc.perform(
        post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isOk()).andReturn();
    return bodyOf(result);
  }

  private ResultActions refresh(String token) throws Exception {
    String body = String.format("{\"refreshToken\": \"%s\"}", token);
    return mockMvc.perform(
        post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  /** Expects a 401 and returns its body. */
  private String refusalBody(ResultActions actions) throws Exception {
    return bodyOf(actions.andExpect(status().isUnauthorized()).andReturn());
  }

  private static String bodyOf(MvcResult result) throws Exception {
    return result.getResponse().getContentAsString(StandardCharsets.UTF_8);
  }

  private static String refreshTokenOf(String json) {
    return JsonPath.read(json, "$.refreshToken");
  }

  private static String accessTokenOf(String json) {
    return JsonPath.read(json, "$.accessToken");
  }

  /** Reads the claims of the refresh token in the body of a login or a refresh. */
  private RefreshTokenClaims refreshClaims(String json) {
    return tokenService.parseRefreshToken(refreshTokenOf(json)).orElseThrow();
  }

  private int countTokens() {
    return Objects.requireNonNull(
        jdbcTemplate.queryForObject("SELECT count(*) FROM refresh_tokens", Integer.class));
  }

  private int countActiveTokens() {
    return Objects.requireNonNull(jdbcTemplate.queryForObject(
        "SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL", Integer.class));
  }

  /** Reads one timestamp column of the stored row of a refresh token. */
  private Instant storedTime(String column, UUID jti) {
    OffsetDateTime value = jdbcTemplate.queryForObject(
        String.format("SELECT %s FROM refresh_tokens WHERE jti = ?", column),
        OffsetDateTime.class, jti);
    return value == null ? null : value.toInstant();
  }
}
