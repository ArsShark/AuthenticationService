package com.grechanikovars.authenticationservice.dto.response;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.service.AccessTokenClaims;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Tests the two ways to build a {@link ValidationResponse}. How empty fields are left out of the
 * JSON is proved in {@code AuthControllerTest}, with the real JSON mapper of the application.
 *
 * <p>The credential id (42) and the user id (7) differ on purpose, so mixing them up fails a
 * test.
 */
class ValidationResponseTest {

  private static final Instant EXPIRES_AT =
      Instant.parse("2026-10-19T10:00:00Z").plus(Duration.ofMinutes(15));

  @Test
  void aValidTokenGivesTheUserTheRoleAndTheExpiry() {
    AccessTokenClaims claims =
        new AccessTokenClaims(42L, 7L, Role.USER, "alice@example.com", EXPIRES_AT);

    ValidationResponse response = ValidationResponse.of(claims);

    assertAll(
        () -> assertTrue(response.valid()),
        () -> assertEquals(7L, response.userId()),
        () -> assertEquals(Role.USER, response.role()),
        () -> assertEquals(EXPIRES_AT, response.expiresAt()));
  }

  @Test
  void anAdminWithoutAProfileHasNoUserId() {
    AccessTokenClaims claims =
        new AccessTokenClaims(42L, null, Role.ADMIN, "admin@example.com", EXPIRES_AT);

    ValidationResponse response = ValidationResponse.of(claims);

    assertAll(
        () -> assertTrue(response.valid()),
        () -> assertNull(response.userId()),
        () -> assertEquals(Role.ADMIN, response.role()));
  }

  @Test
  void aTokenThatIsNotValidHasNothingButTheFlag() {
    ValidationResponse response = ValidationResponse.invalid();

    assertAll(
        () -> assertFalse(response.valid()),
        () -> assertNull(response.userId()),
        () -> assertNull(response.role()),
        () -> assertNull(response.expiresAt()));
  }
}
