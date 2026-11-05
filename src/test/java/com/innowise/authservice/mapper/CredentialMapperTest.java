package com.innowise.authservice.mapper;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.innowise.authservice.TestEntities;
import com.innowise.authservice.dto.response.CredentialResponse;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Checks how an account becomes its public view. The account id (42) and the user id (7) differ
 * on purpose, so mixing them up fails a test.
 */
class CredentialMapperTest {

  private static final Instant CREATED_AT = Instant.parse("2026-10-19T10:00:00Z");

  private final CredentialMapper mapper = new CredentialMapperImpl();

  @Test
  void copiesTheFieldsAndCallsTheUsernameLogin() {
    Credential credential = TestEntities.withDatabaseValues(
        new Credential("alice@example.com", "x".repeat(60), Role.USER, 7L), 42L, CREATED_AT);

    CredentialResponse response = mapper.toResponse(credential);

    assertAll(
        () -> assertEquals(42L, response.id()),
        () -> assertEquals("alice@example.com", response.login()),
        () -> assertEquals(Role.USER, response.role()),
        () -> assertEquals(7L, response.userId()),
        () -> assertEquals(CREATED_AT, response.createdAt()));
  }

  @Test
  void anAdminWithoutAProfileHasNoUserId() {
    Credential credential = TestEntities.withDatabaseValues(
        new Credential("admin@example.com", "x".repeat(60), Role.ADMIN, null), 1L, CREATED_AT);

    CredentialResponse response = mapper.toResponse(credential);

    assertAll(
        () -> assertEquals(Role.ADMIN, response.role()),
        () -> assertNull(response.userId()));
  }
}
