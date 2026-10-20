package com.grechanikovars.authenticationservice.config;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Enables JPA Auditing and feeds it with the time of the application {@link Clock}.
 *
 * <p>Without the custom provider, auditing would read the system time on its own and the
 * timestamps could differ from the ones the services pass explicitly, for example in bulk updates.
 */
@Configuration(proxyBeanMethods = false)
@EnableJpaAuditing(dateTimeProviderRef = "auditingDateTimeProvider")
public class JpaAuditingConfig {

  /**
   * Creates the provider that tells JPA Auditing what time it is.
   *
   * @param clock the application clock
   * @return a provider that returns the current instant of the clock
   */
  @Bean
  public DateTimeProvider auditingDateTimeProvider(Clock clock) {
    return () -> Optional.of(Instant.now(clock));
  }
}
