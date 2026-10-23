package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import com.grechanikovars.authenticationservice.service.AccessTokenClaims;
import com.grechanikovars.authenticationservice.service.RefreshTokenClaims;
import com.grechanikovars.authenticationservice.service.RefreshTokenService;
import com.grechanikovars.authenticationservice.service.TokenPair;
import com.grechanikovars.authenticationservice.service.TokenService;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Tests the storing and the rotation of refresh tokens against a real PostgreSQL, with real
 * signed tokens and the movable test clock.
 *
 * <p>The service is called directly, through its Spring proxy, so every call runs in the real
 * transaction. The checks read the table with plain SQL on another connection, so they see
 * only what was committed: a revocation that was rolled back would show up as a failure.
 */
class RefreshTokenServiceIntegrationTest extends AbstractIntegrationTest {

  private static final int PARALLEL_ROTATIONS = 8;
  private static final Duration REFRESH_TTL = Duration.ofDays(7);

  @Autowired
  private RefreshTokenService refreshTokenService;

  @Autowired
  private TokenService tokenService;

  @Autowired
  private CredentialRepository credentialRepository;

  @Test
  void issuePairStoresTheRefreshTokenByItsJtiAndNeverTheToken() {
    Credential account = account("alice@example.com", 7L);

    TokenPair pair = refreshTokenService.issuePair(account);

    UUID jti = pair.refresh().jti();
    Optional<AccessTokenClaims> access = tokenService.parseAccessToken(pair.access().value());
    Optional<RefreshTokenClaims> refresh = tokenService.parseRefreshToken(pair.refresh().value());
    assertAll(
        () -> assertEquals(1, countTokens(account.getId())),
        () -> assertEquals(account.getId(), credentialIdOf(jti)),
        () -> assertEquals(START.plus(REFRESH_TTL), timestamp(
            "SELECT expires_at FROM refresh_tokens WHERE jti = ?", jti)),
        () -> assertEquals(pair.refresh().expiresAt(), timestamp(
            "SELECT expires_at FROM refresh_tokens WHERE jti = ?", jti)),
        () -> assertEquals(START, timestamp(
            "SELECT created_at FROM refresh_tokens WHERE jti = ?", jti)),
        () -> assertNull(timestamp("SELECT revoked_at FROM refresh_tokens WHERE jti = ?", jti)),
        () -> assertTrue(access.isPresent()),
        () -> assertEquals(Role.USER, access.orElseThrow().role()),
        () -> assertEquals(7L, access.orElseThrow().userId()),
        () -> assertEquals(jti, refresh.orElseThrow().jti()));
  }

  /**
   * The bulk update bypasses JPA Auditing: if {@code updated_at} were not passed explicitly, it
   * would stay at the time of the insert.
   */
  @Test
  void rotateRevokesTheUsedTokenAndStoresTheNewOne() {
    Credential account = account("alice@example.com", 7L);
    TokenPair first = refreshTokenService.issuePair(account);
    RefreshTokenClaims claims = claimsOf(first);
    Instant later = START.plus(Duration.ofMinutes(5));
    clock.set(later);

    Optional<TokenPair> second = refreshTokenService.rotate(claims);

    UUID oldJti = first.refresh().jti();
    UUID newJti = second.orElseThrow().refresh().jti();
    assertAll(
        () -> assertNotEquals(oldJti, newJti),
        () -> assertEquals(later, timestamp(
            "SELECT revoked_at FROM refresh_tokens WHERE jti = ?", oldJti)),
        () -> assertEquals(later, timestamp(
            "SELECT updated_at FROM refresh_tokens WHERE jti = ?", oldJti)),
        () -> assertNull(timestamp("SELECT revoked_at FROM refresh_tokens WHERE jti = ?", newJti)),
        () -> assertEquals(later.plus(REFRESH_TTL), timestamp(
            "SELECT expires_at FROM refresh_tokens WHERE jti = ?", newJti)),
        () -> assertEquals(2, countTokens(account.getId())),
        () -> assertEquals(1, countActiveTokens(account.getId())));
  }

  /** A change of the role in the database acts at the next refresh, not before. */
  @Test
  void rotateTakesTheRoleFromTheDatabase() {
    Credential account = account("alice@example.com", 7L);
    TokenPair first = refreshTokenService.issuePair(account);
    jdbcTemplate.update("UPDATE credentials SET role = 'ADMIN' WHERE id = ?", account.getId());

    TokenPair second = refreshTokenService.rotate(claimsOf(first)).orElseThrow();

    AccessTokenClaims oldAccess =
        tokenService.parseAccessToken(first.access().value()).orElseThrow();
    AccessTokenClaims newAccess =
        tokenService.parseAccessToken(second.access().value()).orElseThrow();
    assertAll(
        () -> assertEquals(Role.USER, oldAccess.role()),
        () -> assertEquals(Role.ADMIN, newAccess.role()),
        () -> assertEquals(7L, newAccess.userId()));
  }

  /**
   * The second use of a token refuses it and revokes the whole account. The checks read the
   * table after the call returned, so the revocation is proved to be committed, not rolled back.
   */
  @Test
  void aUsedTokenIsRefusedAndEveryTokenOfTheAccountIsRevokedAndCommitted() {
    Credential account = account("alice@example.com", 7L);
    TokenPair first = refreshTokenService.issuePair(account);
    RefreshTokenClaims firstClaims = claimsOf(first);
    TokenPair second = refreshTokenService.rotate(firstClaims).orElseThrow();
    Instant reuseTime = START.plus(Duration.ofHours(1));
    clock.set(reuseTime);

    Optional<TokenPair> again = refreshTokenService.rotate(firstClaims);

    assertAll(
        () -> assertTrue(again.isEmpty()),
        () -> assertEquals(0, countActiveTokens(account.getId())),
        () -> assertEquals(2, countTokens(account.getId())),
        () -> assertEquals(reuseTime, timestamp(
            "SELECT revoked_at FROM refresh_tokens WHERE jti = ?", second.refresh().jti())),
        () -> assertEquals(START, timestamp(
            "SELECT revoked_at FROM refresh_tokens WHERE jti = ?", first.refresh().jti())));
  }

  @Test
  void reuseTouchesOnlyTheTokensOfThatAccount() {
    Credential alice = account("alice@example.com", 7L);
    Credential bob = account("bob@example.com", 8L);
    TokenPair alicePair = refreshTokenService.issuePair(alice);
    refreshTokenService.issuePair(bob);
    RefreshTokenClaims aliceClaims = claimsOf(alicePair);
    refreshTokenService.rotate(aliceClaims).orElseThrow();

    refreshTokenService.rotate(aliceClaims);

    assertAll(
        () -> assertEquals(0, countActiveTokens(alice.getId())),
        () -> assertEquals(1, countActiveTokens(bob.getId())));
  }

  /** Two logins make two sessions; using the token of one must not touch the other. */
  @Test
  void aRotationDoesNotTouchAnotherSessionOfTheSameAccount() {
    Credential account = account("alice@example.com", 7L);
    TokenPair phone = refreshTokenService.issuePair(account);
    TokenPair laptop = refreshTokenService.issuePair(account);

    refreshTokenService.rotate(claimsOf(phone)).orElseThrow();

    assertAll(
        () -> assertNull(timestamp(
            "SELECT revoked_at FROM refresh_tokens WHERE jti = ?", laptop.refresh().jti())),
        () -> assertEquals(2, countActiveTokens(account.getId())));
  }

  /**
   * A token with a valid signature that the database does not know is handled like a used one.
   * It cannot be forged, so it can only come from a lost or restored database, and the safe
   * answer is to end the sessions of the account.
   */
  @Test
  void aTokenThatTheDatabaseDoesNotKnowIsTreatedLikeAReuse() {
    Credential account = account("alice@example.com", 7L);
    refreshTokenService.issuePair(account);
    RefreshTokenClaims unknown =
        new RefreshTokenClaims(account.getId(), UUID.randomUUID(), START.plusSeconds(60));

    Optional<TokenPair> result = refreshTokenService.rotate(unknown);

    assertAll(
        () -> assertTrue(result.isEmpty()),
        () -> assertEquals(0, countActiveTokens(account.getId())));
  }

  @Test
  void aTokenOfADeletedAccountIsRefused() {
    Credential account = account("alice@example.com", 7L);
    TokenPair pair = refreshTokenService.issuePair(account);
    jdbcTemplate.update("DELETE FROM credentials WHERE id = ?", account.getId());

    Optional<TokenPair> result = refreshTokenService.rotate(claimsOf(pair));

    assertAll(
        () -> assertTrue(result.isEmpty()),
        () -> assertEquals(0, countTokens(account.getId())));
  }

  /**
   * Eight requests use one token at the same moment. The UPDATE that revokes the token is
   * atomic, so exactly one of them wins and exactly one new row is stored; the others get no
   * pair. The test does not check that the new token still works: the losers revoke every valid
   * token of the account, including the new one (see {@link RefreshTokenService#rotate}).
   */
  @RepeatedTest(5)
  void parallelRotationsOfOneTokenGiveExactlyOneSuccess() throws Exception {
    Credential account = account("alice@example.com", 7L);
    RefreshTokenClaims claims = claimsOf(refreshTokenService.issuePair(account));

    List<Optional<TokenPair>> results = rotateInParallel(claims);

    long succeeded = results.stream().filter(Optional::isPresent).count();
    assertAll(
        () -> assertEquals(PARALLEL_ROTATIONS, results.size()),
        () -> assertEquals(1L, succeeded),
        () -> assertEquals(2, countTokens(account.getId())));
  }

  /**
   * Sends {@value #PARALLEL_ROTATIONS} rotations at the same moment: a barrier releases all
   * threads together. An exception in a thread fails the test, because {@code get()} rethrows it.
   */
  private List<Optional<TokenPair>> rotateInParallel(RefreshTokenClaims claims) throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(PARALLEL_ROTATIONS);
    CyclicBarrier barrier = new CyclicBarrier(PARALLEL_ROTATIONS);
    try {
      List<Callable<Optional<TokenPair>>> tasks = IntStream.range(0, PARALLEL_ROTATIONS)
          .<Callable<Optional<TokenPair>>>mapToObj(i -> () -> {
            barrier.await();
            return refreshTokenService.rotate(claims);
          })
          .toList();
      List<Optional<TokenPair>> results = new ArrayList<>();
      for (Future<Optional<TokenPair>> future : executor.invokeAll(tasks)) {
        results.add(future.get());
      }
      return results;
    } finally {
      executor.shutdownNow();
    }
  }

  /**
   * Creates an account with plain SQL and loads it outside a transaction, so the entity is
   * detached, as it is in a login.
   */
  private Credential account(String login, Long userId) {
    long id = insertCredential(login, "USER", userId);
    return credentialRepository.findById(id).orElseThrow();
  }

  /** Reads the claims of the refresh token of a pair, which also verifies the real token. */
  private RefreshTokenClaims claimsOf(TokenPair pair) {
    return tokenService.parseRefreshToken(pair.refresh().value()).orElseThrow();
  }

  private int countTokens(long credentialId) {
    return Objects.requireNonNull(jdbcTemplate.queryForObject(
        "SELECT count(*) FROM refresh_tokens WHERE credential_id = ?", Integer.class,
        credentialId));
  }

  private int countActiveTokens(long credentialId) {
    return Objects.requireNonNull(jdbcTemplate.queryForObject(
        "SELECT count(*) FROM refresh_tokens WHERE credential_id = ? AND revoked_at IS NULL",
        Integer.class, credentialId));
  }

  private long credentialIdOf(UUID jti) {
    return Objects.requireNonNull(jdbcTemplate.queryForObject(
        "SELECT credential_id FROM refresh_tokens WHERE jti = ?", Long.class, jti));
  }

  /** Reads one timestamp of the row with this {@code jti}; {@code null} for an empty column. */
  private Instant timestamp(String query, UUID jti) {
    OffsetDateTime value = jdbcTemplate.queryForObject(query, OffsetDateTime.class, jti);
    return value == null ? null : value.toInstant();
  }
}
