package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Checks the rules of the {@code credentials} table that the database itself enforces.
 */
class CredentialConstraintsIntegrationTest extends AbstractIntegrationTest {

  @Test
  void duplicateLoginIsRejected() {
    insertCredential("a@x.com", "USER", 1L);

    DataIntegrityViolationException error = assertThrows(DataIntegrityViolationException.class,
        () -> insertCredential("a@x.com", "USER", 2L));

    assertEquals("uq_credentials_login", violatedConstraint(error));
  }

  @Test
  void duplicateUserIdIsRejected() {
    insertCredential("a@x.com", "USER", 1L);

    DataIntegrityViolationException error = assertThrows(DataIntegrityViolationException.class,
        () -> insertCredential("b@x.com", "USER", 1L));

    assertEquals("uq_credentials_user_id", violatedConstraint(error));
  }

  @Test
  void unknownRoleIsRejected() {
    DataIntegrityViolationException error = assertThrows(DataIntegrityViolationException.class,
        () -> insertCredential("a@x.com", "ROOT", 1L));

    assertEquals("ck_credentials_role", violatedConstraint(error));
  }

  @Test
  void userWithoutProfileIsRejected() {
    DataIntegrityViolationException error = assertThrows(DataIntegrityViolationException.class,
        () -> insertCredential("a@x.com", "USER", null));

    assertEquals("ck_credentials_user_id_required", violatedConstraint(error));
  }

  /** PostgreSQL treats NULLs as distinct in a UNIQUE constraint, so this must work. */
  @Test
  void severalAdminsWithoutProfileAreAllowed() {
    insertCredential("admin1@x.com", "ADMIN", null);
    insertCredential("admin2@x.com", "ADMIN", null);

    Integer count = jdbcTemplate.queryForObject(
        "SELECT count(*) FROM credentials WHERE user_id IS NULL", Integer.class);

    assertEquals(2, count);
  }
}
