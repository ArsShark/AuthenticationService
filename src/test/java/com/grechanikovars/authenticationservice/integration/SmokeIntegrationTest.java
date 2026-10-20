package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.time.Clock;
import java.util.List;
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
}
