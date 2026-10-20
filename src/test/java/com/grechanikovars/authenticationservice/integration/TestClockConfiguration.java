package com.grechanikovars.authenticationservice.integration;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Replaces the application {@link java.time.Clock} with a {@link MutableClock} in integration
 * tests.
 *
 * <p>The bean is {@code @Primary}, so JPA Auditing and every service get the test clock.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestClockConfiguration {

  @Bean
  @Primary
  public MutableClock mutableClock() {
    return new MutableClock(AbstractIntegrationTest.START);
  }
}
