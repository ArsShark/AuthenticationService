package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.RefreshToken;
import com.grechanikovars.authenticationservice.entity.Role;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Checks that the entities are stored as mapped and that JPA Auditing uses the application clock.
 */
class EntityPersistenceIntegrationTest extends AbstractIntegrationTest {

  @PersistenceContext
  private EntityManager entityManager;

  @Autowired
  private PlatformTransactionManager transactionManager;

  private TransactionTemplate transaction;

  @BeforeEach
  void createTransactionTemplate() {
    transaction = new TransactionTemplate(transactionManager);
  }

  @Test
  void credentialAndTokenAreStoredAsMapped() {
    UUID jti = UUID.randomUUID();
    Credential credential = new Credential("a@x.com", HASH, Role.USER, 7L);

    transaction.executeWithoutResult(status -> {
      entityManager.persist(credential);
      entityManager.persist(new RefreshToken(jti, credential, START.plus(Duration.ofDays(7))));
    });

    Credential loaded = transaction.execute(
        status -> entityManager.find(Credential.class, credential.getId()));
    assertAll(
        () -> assertEquals("USER", sql("SELECT role FROM credentials", String.class)),
        () -> assertEquals(7L, sql("SELECT user_id FROM credentials", Long.class)),
        () -> assertEquals(credential.getId(),
            sql("SELECT credential_id FROM refresh_tokens", Long.class)),
        () -> assertEquals(jti, sql("SELECT jti FROM refresh_tokens", UUID.class)),
        () -> assertNull(sql("SELECT revoked_at FROM refresh_tokens", OffsetDateTime.class)),
        () -> assertEquals("a@x.com", loaded.getLogin()),
        () -> assertEquals(Role.USER, loaded.getRole()),
        () -> assertEquals(HASH, loaded.getPasswordHash()));
  }

  @Test
  void createdAtAndUpdatedAtComeFromTheClock() {
    Credential credential = new Credential("a@x.com", HASH, Role.USER, 7L);
    RefreshToken token = new RefreshToken(UUID.randomUUID(), credential, START.plusSeconds(60));

    transaction.executeWithoutResult(status -> {
      entityManager.persist(credential);
      entityManager.persist(token);
    });

    assertAll(
        () -> assertEquals(START, credential.getCreatedAt()),
        () -> assertEquals(START, credential.getUpdatedAt()),
        () -> assertEquals(START, token.getCreatedAt()),
        () -> assertEquals(START, token.getUpdatedAt()),
        () -> assertEquals(START, storedInstant("SELECT created_at FROM credentials")),
        () -> assertEquals(START, storedInstant("SELECT updated_at FROM refresh_tokens")));
  }

  @Test
  void auditingFollowsTheClockWhenItMoves() {
    Instant later = START.plus(Duration.ofHours(1));
    clock.set(later);
    Credential credential = new Credential("a@x.com", HASH, Role.ADMIN, null);

    transaction.executeWithoutResult(status -> entityManager.persist(credential));

    assertAll(
        () -> assertEquals(later, credential.getCreatedAt()),
        () -> assertEquals(later, storedInstant("SELECT created_at FROM credentials")));
  }

  /** Reads the single value of a query that returns exactly one row. */
  private <T> T sql(String query, Class<T> type) {
    return jdbcTemplate.queryForObject(query, type);
  }

  private Instant storedInstant(String query) {
    return sql(query, OffsetDateTime.class).toInstant();
  }
}
