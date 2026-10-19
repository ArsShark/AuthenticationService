package com.grechanikovars.authenticationservice.integration;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Objects;

/**
 * A {@link Clock} whose time a test can set.
 *
 * <p>A fixed clock would make {@code createdAt} and {@code updatedAt} equal forever. A movable
 * one lets a test prove that the code reads the clock at the moment of the operation.
 */
public final class MutableClock extends Clock {

  private final ZoneId zone;
  private volatile Instant instant;

  /**
   * Creates a UTC clock that shows the given instant.
   *
   * @param instant the initial time
   */
  public MutableClock(Instant instant) {
    this(instant, ZoneOffset.UTC);
  }

  private MutableClock(Instant instant, ZoneId zone) {
    this.instant = Objects.requireNonNull(instant);
    this.zone = Objects.requireNonNull(zone);
  }

  /**
   * Moves the clock to the given instant.
   *
   * @param instant the new time
   */
  public void set(Instant instant) {
    this.instant = Objects.requireNonNull(instant);
  }

  @Override
  public ZoneId getZone() {
    return zone;
  }

  /** Returns a copy that starts at the current time and is NOT linked to this clock. */
  @Override
  public Clock withZone(ZoneId zone) {
    return new MutableClock(instant, zone);
  }

  @Override
  public Instant instant() {
    return instant;
  }
}
