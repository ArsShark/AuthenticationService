package com.grechanikovars.authenticationservice;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Provides a throwaway PostgreSQL container for Spring tests.
 *
 * <p>{@link ServiceConnection} makes Spring Boot point the datasource at the container, so tests
 * need no environment variables and never touch the local development database. Import this
 * class into a test with {@code @Import}.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

  @Bean
  @ServiceConnection
  PostgreSQLContainer postgresContainer() {
    return new PostgreSQLContainer("postgres:18");
  }
}
