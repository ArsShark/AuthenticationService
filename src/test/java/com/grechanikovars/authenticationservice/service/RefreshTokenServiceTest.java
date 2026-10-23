package com.grechanikovars.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.grechanikovars.authenticationservice.TestEntities;
import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.RefreshToken;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import com.grechanikovars.authenticationservice.repository.RefreshTokenRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RefreshTokenService}: plain Mockito, no Spring, no database.
 *
 * <p>They pin which branch does what. The atomic revocation and the races are proved against a
 * real PostgreSQL in {@code RefreshTokenServiceIntegrationTest}.
 *
 * <p>The credential id (42) and the user id (7) differ on purpose, so mixing them up fails a
 * test.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

  private static final long CREDENTIAL_ID = 42L;
  private static final long USER_ID = 7L;
  private static final Instant NOW = Instant.parse("2026-10-19T10:00:00Z");
  private static final String HASH = "h".repeat(60);

  @Mock
  private RefreshTokenRepository refreshTokens;

  @Mock
  private CredentialRepository credentials;

  @Mock
  private TokenService tokens;

  private final Credential credential = TestEntities.withDatabaseValues(
      new Credential("user@example.com", HASH, Role.USER, USER_ID), CREDENTIAL_ID, NOW);
  private final IssuedToken access =
      new IssuedToken("access-value", UUID.randomUUID(), NOW, NOW.plus(Duration.ofMinutes(15)));
  private final IssuedToken refresh =
      new IssuedToken("refresh-value", UUID.randomUUID(), NOW, NOW.plus(Duration.ofDays(7)));

  private RefreshTokenService service;

  @BeforeEach
  void setUp() {
    Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    service = new RefreshTokenService(refreshTokens, credentials, tokens, clock);
  }

  @Test
  void issuePairStoresOnlyTheJtiAndTheExpiryOfTheRefreshToken() {
    stubIssuing();

    TokenPair pair = service.issuePair(credential);

    ArgumentCaptor<RefreshToken> saved = ArgumentCaptor.forClass(RefreshToken.class);
    verify(refreshTokens).save(saved.capture());
    RefreshToken row = saved.getValue();
    assertAll(
        () -> assertSame(access, pair.access()),
        () -> assertSame(refresh, pair.refresh()),
        () -> assertEquals(refresh.jti(), row.getJti()),
        () -> assertEquals(refresh.expiresAt(), row.getExpiresAt()),
        () -> assertSame(credential, row.getCredential()),
        () -> assertNull(row.getRevokedAt()));
  }

  @Test
  void rotateRevokesTheUsedTokenAtTheClockTimeAndStoresTheNewOne() {
    UUID usedJti = UUID.randomUUID();
    when(refreshTokens.revokeByJti(usedJti, NOW)).thenReturn(1);
    when(credentials.findById(CREDENTIAL_ID)).thenReturn(Optional.of(credential));
    stubIssuing();

    Optional<TokenPair> result = service.rotate(claimsOf(usedJti));

    ArgumentCaptor<RefreshToken> saved = ArgumentCaptor.forClass(RefreshToken.class);
    verify(refreshTokens).save(saved.capture());
    assertAll(
        () -> assertTrue(result.isPresent()),
        () -> assertSame(refresh, result.orElseThrow().refresh()),
        () -> assertEquals(refresh.jti(), saved.getValue().getJti()),
        () -> assertNotEquals(usedJti, saved.getValue().getJti()));
    verify(refreshTokens, never()).revokeAllByCredentialId(any(), any());
  }

  /** A token that cannot be used revokes the rest of the account and issues nothing. */
  @Test
  void rotateOfATokenThatIsNotValidRevokesTheWholeAccountAndIssuesNothing() {
    UUID usedJti = UUID.randomUUID();
    when(refreshTokens.revokeByJti(usedJti, NOW)).thenReturn(0);
    when(refreshTokens.revokeAllByCredentialId(CREDENTIAL_ID, NOW)).thenReturn(3);

    Optional<TokenPair> result = service.rotate(claimsOf(usedJti));

    assertTrue(result.isEmpty());
    verifyNoInteractions(tokens, credentials);
    verify(refreshTokens, never()).save(any(RefreshToken.class));
  }

  /** The account can disappear between the revocation and the read; then nothing is issued. */
  @Test
  void rotateIssuesNothingIfTheAccountIsGone() {
    UUID usedJti = UUID.randomUUID();
    when(refreshTokens.revokeByJti(usedJti, NOW)).thenReturn(1);
    when(credentials.findById(CREDENTIAL_ID)).thenReturn(Optional.empty());

    Optional<TokenPair> result = service.rotate(claimsOf(usedJti));

    assertTrue(result.isEmpty());
    verifyNoInteractions(tokens);
    verify(refreshTokens, never()).save(any(RefreshToken.class));
    verify(refreshTokens, never()).revokeAllByCredentialId(any(), any());
  }

  private RefreshTokenClaims claimsOf(UUID jti) {
    return new RefreshTokenClaims(CREDENTIAL_ID, jti, NOW.plus(Duration.ofDays(1)));
  }

  private void stubIssuing() {
    when(tokens.issueAccessToken(credential)).thenReturn(access);
    when(tokens.issueRefreshToken(credential)).thenReturn(refresh);
  }
}
