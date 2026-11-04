package com.innowise.authservice.integration;

import com.innowise.authservice.service.Pause;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A {@link Pause} that does not wait: it records the requested durations, so a test can check
 * that the retries paused as designed without sleeping.
 */
public class RecordingPause implements Pause {

  private final List<Duration> pauses = new CopyOnWriteArrayList<>();

  @Override
  public void sleep(Duration duration) {
    pauses.add(duration);
  }

  /** The durations requested so far, in order. */
  public List<Duration> pauses() {
    return List.copyOf(pauses);
  }

  /** Forgets the recorded durations. */
  public void reset() {
    pauses.clear();
  }
}
