package com.innowise.authservice.service;

import java.time.Duration;
import org.springframework.stereotype.Component;

/** The real {@link Pause}: blocks the calling thread. */
@Component
class ThreadPause implements Pause {

  @Override
  public void sleep(Duration duration) throws InterruptedException {
    Thread.sleep(duration);
  }
}
