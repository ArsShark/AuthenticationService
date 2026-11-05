package com.innowise.authservice.integration;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Replaces the real {@link com.innowise.authservice.service.Pause} with a {@link RecordingPause}
 * in integration tests, so the retries of the undoing never wait.
 *
 * <p>The bean is {@code @Primary}, so the services get the recording pause.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestPauseConfiguration {

  @Bean
  @Primary
  public RecordingPause recordingPause() {
    return new RecordingPause();
  }
}
