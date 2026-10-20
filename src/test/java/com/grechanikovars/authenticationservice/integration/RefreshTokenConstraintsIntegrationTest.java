package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Checks the rules of the {@code refresh_tokens} table that the database itself enforces.
 */
class RefreshTokenConstraintsIntegrationTest extends AbstractIntegrationTest {

  @Test
  void duplicateJtiIsRejected() {
    long credentialId = insertCredential("a@x.com", "USER", 1L);
    UUID jti = UUID.randomUUID();
    insertRefreshToken(jti, credentialId);

    DataIntegrityViolationException error = assertThrows(DataIntegrityViolationException.class,
        () -> insertRefreshToken(jti, credentialId));

    assertEquals("uq_refresh_tokens_jti", violatedConstraint(error));
  }

  @Test
  void unknownCredentialIsRejected() {
    DataIntegrityViolationException error = assertThrows(DataIntegrityViolationException.class,
        () -> insertRefreshToken(UUID.randomUUID(), 999L));

    assertEquals("fk_refresh_tokens_credential", violatedConstraint(error));
  }

  @Test
  void deletingCredentialDeletesOnlyItsOwnTokens() {
    long first = insertCredential("a@x.com", "USER", 1L);
    long second = insertCredential("b@x.com", "USER", 2L);
    insertRefreshToken(UUID.randomUUID(), first);
    insertRefreshToken(UUID.randomUUID(), first);
    insertRefreshToken(UUID.randomUUID(), second);

    jdbcTemplate.update("DELETE FROM credentials WHERE id = ?", first);

    assertAll(
        () -> assertEquals(0, tokensOf(first)),
        () -> assertEquals(1, tokensOf(second)));
  }

  private int tokensOf(long credentialId) {
    Integer count = jdbcTemplate.queryForObject(
        "SELECT count(*) FROM refresh_tokens WHERE credential_id = ?", Integer.class, credentialId);
    return count;
  }
}
