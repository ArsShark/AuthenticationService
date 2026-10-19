package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Checks that the application starts against a real PostgreSQL and is wired as expected.
 */
class SmokeIntegrationTest extends AbstractIntegrationTest {

  @Autowired
  private Clock applicationClock;

  /** A failure here means a wiring problem or a mismatch found by {@code ddl-auto: validate}. */
  @Test
  void contextLoads() {
    // Starting the context is the whole test.
  }

  @Test
  void liquibaseAppliesBothChangeSetsInOrder() {
    List<String> applied = jdbcTemplate.queryForList(
        "SELECT id FROM databasechangelog ORDER BY orderexecuted", String.class);

    assertEquals(List.of("create-credentials-table", "create-refresh-tokens-table"), applied);
  }

  @Test
  void testClockReplacesTheApplicationClock() {
    assertSame(clock, applicationClock);
  }

  /**
   * At WARN, Hibernate logs the DETAIL of a failed statement, and that is the whole failing row,
   * including the password hash. The logger must stay at ERROR.
   */
  @Test
  void hibernateJdbcErrorLoggerDoesNotLogWarnings() {
    Logger logger = LogManager.getLogger("org.hibernate.orm.jdbc.error");

    assertAll(
        () -> assertFalse(logger.isWarnEnabled()),
        () -> assertTrue(logger.isErrorEnabled()));
  }
}
