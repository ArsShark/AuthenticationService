package com.grechanikovars.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.data.auditing.DateTimeProvider;

/**
 * Checks that JPA Auditing takes its time from the application clock.
 */
class JpaAuditingConfigTest {

  private static final Instant NOW = Instant.parse("2026-10-18T12:00:00Z");

  @Test
  void auditingDateTimeProviderReturnsTheInstantOfTheClock() {
    Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    DateTimeProvider provider = new JpaAuditingConfig().auditingDateTimeProvider(clock);

    assertEquals(Optional.of(NOW), provider.getNow());
  }

  @Test
  void applicationClockRunsInUtc() {
    Clock clock = new ClockConfig().clock();

    assertEquals(ZoneOffset.UTC, clock.getZone());
  }
}
