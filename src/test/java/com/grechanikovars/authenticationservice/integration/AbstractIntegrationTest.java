package com.grechanikovars.authenticationservice.integration;

import com.grechanikovars.authenticationservice.TestcontainersConfiguration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Base class of all integration tests.
 *
 * <p>Every subclass shares ONE Spring context and one PostgreSQL container, because the
 * container is a bean of the context. So subclasses must not add {@code @MockitoBean},
 * {@code @TestPropertySource}, {@code @DirtiesContext} or an extra {@code @Import}: each of them
 * would create a new context and a new container. The properties of the context are set in the
 * {@code @SpringBootTest} annotation of this class, for all subclasses at once; the first admin
 * is switched off there, so an {@code ADMIN_LOGIN} in the environment of a developer cannot change
 * a test. Tests are not
 * {@code @Transactional}, so they see real commits; {@link #resetState()} cleans up before every
 * test.
 */
@Tag("integration")
@SpringBootTest(properties = {
    "app.internal.api-key=test-internal-key",
    "app.admin.login=",
    "app.admin.password="
})
@AutoConfigureMockMvc
@Import({TestcontainersConfiguration.class, TestClockConfiguration.class})
public abstract class AbstractIntegrationTest {

  /** The time of the test clock at the start of every test; far in the past on purpose. */
  protected static final Instant START = Instant.parse("2026-01-15T10:00:00Z");

  /** A string that looks like a BCrypt hash by length: 60 characters. */
  protected static final String HASH = "x".repeat(60);

  @Autowired
  protected JdbcTemplate jdbcTemplate;

  /** Sends requests through the whole stack, from the servlet layer to the database. */
  @Autowired
  protected MockMvc mockMvc;

  @Autowired
  protected MutableClock clock;

  @BeforeEach
  void resetState() {
    jdbcTemplate.execute("TRUNCATE refresh_tokens, credentials RESTART IDENTITY");
    clock.set(START);
  }

  /**
   * Inserts a row into {@code credentials} with plain SQL, so a test can also break the rules.
   *
   * @return the generated id
   */
  protected long insertCredential(String login, String role, Long userId) {
    Long id = jdbcTemplate.queryForObject("""
        INSERT INTO credentials (login, password_hash, role, user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, now(), now())
        RETURNING id
        """, Long.class, login, HASH, role, userId);
    return Objects.requireNonNull(id);
  }

  /** Inserts a valid refresh token (it expires in 7 days) with plain SQL. */
  protected void insertRefreshToken(UUID jti, long credentialId) {
    jdbcTemplate.update("""
        INSERT INTO refresh_tokens (jti, credential_id, expires_at, created_at, updated_at)
        VALUES (?, ?, now() + interval '7 days', now(), now())
        """, jti, credentialId);
  }

  /**
   * Finds the name of the violated constraint in the cause chain of a database error.
   *
   * <p>The name comes from the structured field of the server error, so it does not depend on
   * the language of the server messages.
   */
  protected static String violatedConstraint(Throwable error) {
    for (Throwable cause = error; cause != null; cause = cause.getCause()) {
      if (cause instanceof PSQLException psql && psql.getServerErrorMessage() != null) {
        return psql.getServerErrorMessage().getConstraint();
      }
    }
    throw new AssertionError("No PostgreSQL error in the cause chain", error);
  }
}
