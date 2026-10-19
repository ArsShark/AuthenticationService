package com.grechanikovars.authenticationservice.dto.response;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.grechanikovars.authenticationservice.TestEntities;
import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Checks what the public view of an account contains.
 */
class CredentialResponseTest {

  private static final Instant CREATED_AT = Instant.parse("2026-10-19T10:00:00Z");

  @Test
  void fromCopiesTheFieldsOfTheAccount() {
    Credential credential = TestEntities.withDatabaseValues(
        new Credential("alice@example.com", "x".repeat(60), Role.USER, 7L), 42L, CREATED_AT);

    CredentialResponse response = CredentialResponse.from(credential);

    assertAll(
        () -> assertEquals(42L, response.id()),
        () -> assertEquals("alice@example.com", response.login()),
        () -> assertEquals(Role.USER, response.role()),
        () -> assertEquals(7L, response.userId()),
        () -> assertEquals(CREATED_AT, response.createdAt()));
  }

  /** A new component here must be a conscious decision: the hash must never be added. */
  @Test
  void responseHasNoPasswordHash() {
    List<String> components = Arrays.stream(CredentialResponse.class.getRecordComponents())
        .map(RecordComponent::getName)
        .toList();

    assertEquals(List.of("id", "login", "role", "userId", "createdAt"), components);
  }
}
