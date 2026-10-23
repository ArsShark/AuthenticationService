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
    service = new AuthService(credentials, passwordEncoder, refreshTokens);
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
}
