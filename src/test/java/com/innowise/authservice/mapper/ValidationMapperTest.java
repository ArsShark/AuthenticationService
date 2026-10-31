package com.innowise.authservice.mapper;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.innowise.authservice.dto.response.ValidationResponse;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.service.AccessTokenClaims;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Tests the answer for a valid token. The credential id (42) and the user id (7) differ on
 * purpose, so mixing them up fails a test.
 */
class ValidationMapperTest {

  private static final Instant EXPIRES_AT =
      Instant.parse("2026-10-19T10:00:00Z").plus(Duration.ofMinutes(15));

  private final ValidationMapper mapper = new ValidationMapperImpl();

  @Test
  void aValidTokenGivesTheUserTheRoleAndTheExpiry() {
    AccessTokenClaims claims =
        new AccessTokenClaims(42L, 7L, Role.USER, "alice@example.com", EXPIRES_AT);

    ValidationResponse response = mapper.toResponse(claims);

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

    ValidationResponse response = mapper.toResponse(claims);

    assertAll(
        () -> assertTrue(response.valid()),
        () -> assertNull(response.userId()),
        () -> assertEquals(Role.ADMIN, response.role()));
  }
}
