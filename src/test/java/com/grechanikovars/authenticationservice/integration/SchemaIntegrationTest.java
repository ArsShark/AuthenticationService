package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Checks that the schema created by Liquibase has exactly the documented constraints and indexes.
 *
 * <p>The names matter: the error handler recognizes a unique violation by the {@code uq_} name.
 */
class SchemaIntegrationTest extends AbstractIntegrationTest {

  @Test
  void constraintsHaveTheDocumentedNames() {
    assertAll(
        () -> assertEquals(
            Set.of(
                "pk_credentials",
                "uq_credentials_login",
                "uq_credentials_user_id",
                "ck_credentials_role",
                "ck_credentials_user_id_required"),
            constraintsOf("credentials")),
        () -> assertEquals(
            Set.of(
                "pk_refresh_tokens",
                "uq_refresh_tokens_jti",
                "fk_refresh_tokens_credential"),
            constraintsOf("refresh_tokens")));
  }

  @Test
  void indexesAreTheDocumentedOnes() {
    assertAll(
        () -> assertEquals(
            Set.of("pk_credentials", "uq_credentials_login", "uq_credentials_user_id"),
            indexesOf("credentials")),
        () -> assertEquals(
            Set.of(
                "pk_refresh_tokens",
                "uq_refresh_tokens_jti",
                "idx_refresh_tokens_credential_id"),
            indexesOf("refresh_tokens")));
  }

  /** Primary key, unique, check and foreign key constraints (NOT NULL is not included). */
  private Set<String> constraintsOf(String table) {
    return new HashSet<>(jdbcTemplate.queryForList("""
        SELECT conname FROM pg_constraint
        WHERE conrelid = to_regclass(?) AND contype IN ('p', 'u', 'c', 'f')
        """, String.class, table));
  }

  private Set<String> indexesOf(String table) {
    return new HashSet<>(jdbcTemplate.queryForList("""
        SELECT indexname FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = ?
        """, String.class, table));
  }
}
