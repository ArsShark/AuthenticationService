package com.grechanikovars.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.grechanikovars.authenticationservice.TestEntities;
import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.exception.InvalidCredentialsException;
import com.grechanikovars.authenticationservice.exception.InvalidRefreshTokenException;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Unit tests of {@link AuthService}: plain Mockito, no Spring, no database. The real BCrypt and
 * the real database are used by {@code LoginIntegrationTest}.
 *
 * <p>The credential id (42) and the user id (7) differ on purpose, so mixing them up fails a
 * test.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

  private static final long CREDENTIAL_ID = 42L;
  private static final long USER_ID = 7L;
  private static final Instant NOW = Instant.parse("2026-10-19T10:00:00Z");
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final String STORED_HASH = "stored-hash";
  private static final String DUMMY_HASH = "dummy-hash";

  @Mock
  private CredentialRepository credentials;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private RefreshTokenService refreshTokens;

  @Mock
  private TokenService tokens;

  private final Credential account = TestEntities.withDatabaseValues(
      new Credential("alice@example.com", STORED_HASH, Role.USER, USER_ID), CREDENTIAL_ID, NOW);
  private final TokenPair pair = new TokenPair(
      new IssuedToken("access-value", UUID.randomUUID(), NOW, NOW.plus(Duration.ofMinutes(15))),
      new IssuedToken("refresh-value", UUID.randomUUID(), NOW, NOW.plus(Duration.ofDays(7))));

  private AuthService service;

  @BeforeEach
  void setUp() {
    // The service hashes a dummy password when it is created.
    when(passwordEncoder.encode(anyString())).thenReturn(DUMMY_HASH);
    service = new AuthService(credentials, passwordEncoder, refreshTokens, tokens);
  }

  @Test
  void loginIssuesAPairForTheAccountWhenThePasswordMatches() {
    when(credentials.findByLogin("alice@example.com")).thenReturn(Optional.of(account));
    when(passwordEncoder.matches(PASSWORD, STORED_HASH)).thenReturn(true);
    when(refreshTokens.issuePair(account)).thenReturn(pair);

    TokenPair result = service.login("alice@example.com", PASSWORD);

    assertSame(pair, result);
  }

  /** Registration stores logins stripped and lowercase, so a login must be looked up that way. */
  @Test
  void loginIsStrippedAndLowercasedLikeAtRegistration() {
    when(credentials.findByLogin("alice@example.com")).thenReturn(Optional.of(account));
    when(passwordEncoder.matches(PASSWORD, STORED_HASH)).thenReturn(true);
    when(refreshTokens.issuePair(account)).thenReturn(pair);

    TokenPair result = service.login("  Alice@Example.COM ", PASSWORD);

    assertSame(pair, result);
  }

  @Test
  void aWrongPasswordIsRefusedAndNothingIsIssued() {
    when(credentials.findByLogin("alice@example.com")).thenReturn(Optional.of(account));
    when(passwordEncoder.matches(PASSWORD, STORED_HASH)).thenReturn(false);

    assertThrows(InvalidCredentialsException.class,
        () -> service.login("alice@example.com", PASSWORD));

    verifyNoInteractions(refreshTokens);
  }

  /**
   * The comparison with the dummy hash costs the same time as a real one, so the answer does not
   * show whether the login exists. Its result must be ignored: the mock says "matches" here, and
   * the login must still fail.
   */
  @Test
  void anUnknownLoginIsRefusedAfterTheSameHashComparison() {
    when(credentials.findByLogin("nobody@example.com")).thenReturn(Optional.empty());
    when(passwordEncoder.matches(PASSWORD, DUMMY_HASH)).thenReturn(true);

    assertThrows(InvalidCredentialsException.class,
        () -> service.login("nobody@example.com", PASSWORD));

    verify(passwordEncoder).matches(PASSWORD, DUMMY_HASH);
    verifyNoInteractions(refreshTokens);
  }

  /** BCrypt would cut the password at 72 bytes, so a longer one is never given to it. */
  @Test
  void aPasswordOfMoreThan72BytesIsRefusedWithoutBeingCompared() {
    String tooLong = "a".repeat(73);
    when(credentials.findByLogin("alice@example.com")).thenReturn(Optional.of(account));

    assertThrows(InvalidCredentialsException.class,
        () -> service.login("alice@example.com", tooLong));

    verify(passwordEncoder, never()).matches(eq(tooLong), anyString());
    verifyNoInteractions(refreshTokens);
  }

  @Test
  void aPasswordOfExactly72BytesIsStillChecked() {
    String longest = "a".repeat(72);
    when(credentials.findByLogin("alice@example.com")).thenReturn(Optional.of(account));
    when(passwordEncoder.matches(longest, STORED_HASH)).thenReturn(true);
    when(refreshTokens.issuePair(account)).thenReturn(pair);

    assertSame(pair, service.login("alice@example.com", longest));
  }

  @Test
  void bothFailuresLookTheSameAndNeitherRepeatsTheLogin() {
    when(credentials.findByLogin("alice@example.com")).thenReturn(Optional.of(account));
    when(credentials.findByLogin("nobody@example.com")).thenReturn(Optional.empty());

    InvalidCredentialsException wrongPassword = assertThrows(InvalidCredentialsException.class,
        () -> service.login("alice@example.com", PASSWORD));
    InvalidCredentialsException unknownLogin = assertThrows(InvalidCredentialsException.class,
        () -> service.login("nobody@example.com", PASSWORD));

    assertAll(
        () -> assertEquals(wrongPassword.getMessage(), unknownLogin.getMessage()),
        () -> assertEquals(InvalidCredentialsException.MESSAGE, wrongPassword.getMessage()),
        () -> assertFalse(wrongPassword.getMessage().contains("alice")),
        () -> assertNull(wrongPassword.getCause()),
        () -> assertNull(unknownLogin.getCause()));
  }

  @Test
  void refreshReturnsTheNewPairOfTheRotation() {
    RefreshTokenClaims claims = claimsOf(UUID.randomUUID());
    when(tokens.parseRefreshToken("refresh-value")).thenReturn(Optional.of(claims));
    when(refreshTokens.rotate(claims)).thenReturn(Optional.of(pair));

    TokenPair result = service.refresh("refresh-value");

    assertSame(pair, result);
  }

  /** Garbage, an expired token and an access token never reach the database. */
  @Test
  void refreshOfATokenThatIsNotValidIsRefusedWithoutTouchingTheDatabase() {
    when(tokens.parseRefreshToken("garbage")).thenReturn(Optional.empty());

    assertThrows(InvalidRefreshTokenException.class, () -> service.refresh("garbage"));

    verifyNoInteractions(refreshTokens, credentials);
  }

  @Test
  void refreshOfATokenThatTheRotationRefusesIsRefused() {
    RefreshTokenClaims claims = claimsOf(UUID.randomUUID());
    when(tokens.parseRefreshToken("used-value")).thenReturn(Optional.of(claims));
    when(refreshTokens.rotate(claims)).thenReturn(Optional.empty());

    assertThrows(InvalidRefreshTokenException.class, () -> service.refresh("used-value"));
  }

  /** Both refusals end in the same exception, so the answer cannot show which check failed. */
  @Test
  void bothRefusalsOfARefreshLookTheSame() {
    RefreshTokenClaims claims = claimsOf(UUID.randomUUID());
    when(tokens.parseRefreshToken("garbage")).thenReturn(Optional.empty());
    when(tokens.parseRefreshToken("used-value")).thenReturn(Optional.of(claims));
    when(refreshTokens.rotate(claims)).thenReturn(Optional.empty());

    InvalidRefreshTokenException notValid = assertThrows(InvalidRefreshTokenException.class,
        () -> service.refresh("garbage"));
    InvalidRefreshTokenException notUsable = assertThrows(InvalidRefreshTokenException.class,
        () -> service.refresh("used-value"));

    assertAll(
        () -> assertEquals(notValid.getMessage(), notUsable.getMessage()),
        () -> assertEquals(InvalidRefreshTokenException.MESSAGE, notValid.getMessage()),
        () -> assertFalse(notValid.getMessage().contains("garbage")),
        () -> assertNull(notValid.getCause()),
        () -> assertNull(notUsable.getCause()));
  }

  private RefreshTokenClaims claimsOf(UUID jti) {
    return new RefreshTokenClaims(CREDENTIAL_ID, jti, NOW.plus(Duration.ofDays(1)));
  }

  /** The answer comes from the token alone: the database is not asked. */
  @Test
  void validateReturnsTheClaimsOfAValidAccessToken() {
    AccessTokenClaims claims = new AccessTokenClaims(CREDENTIAL_ID, USER_ID, Role.USER,
        "alice@example.com", NOW.plus(Duration.ofMinutes(15)));
    when(tokens.parseAccessToken("access-value")).thenReturn(Optional.of(claims));

    Optional<AccessTokenClaims> result = service.validate("access-value");

    assertEquals(Optional.of(claims), result);
    verifyNoInteractions(credentials, refreshTokens);
  }

  @Test
  void validateOfATokenThatIsNotValidIsEmpty() {
    when(tokens.parseAccessToken("garbage")).thenReturn(Optional.empty());

    Optional<AccessTokenClaims> result = service.validate("garbage");

    assertEquals(Optional.empty(), result);
    verifyNoInteractions(credentials, refreshTokens);
  }
}
