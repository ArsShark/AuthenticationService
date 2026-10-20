package com.grechanikovars.authenticationservice.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Provides the {@link Clock} that is the only source of the current time in the service.
 *
 * <p>Code never calls {@code Instant.now()} directly. It asks this clock instead, so tests can
 * replace it with a fixed or a movable one.
 */
@Configuration(proxyBeanMethods = false)
public class ClockConfig {

  /**
   * Creates the application clock.
   *
   * @return a clock that runs in UTC
   */
  @Bean
  public Clock clock() {
    return Clock.systemUTC();
  }
}
