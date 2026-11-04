package com.innowise.authservice.service;

import java.time.Duration;

/**
 * Waits for a while between two attempts of a call.
 *
 * <p>It is an interface only so that tests can replace the real wait with one that records the
 * requested durations and returns at once: no test needs to sleep.
 */
@FunctionalInterface
public interface Pause {

  /**
   * Waits.
   *
   * @param duration how long to wait
   * @throws InterruptedException if the thread is interrupted while it waits
   */
  void sleep(Duration duration) throws InterruptedException;
}
