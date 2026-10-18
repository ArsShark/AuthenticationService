package com.grechanikovars.authenticationservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Checks that the application context starts against a real PostgreSQL container.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class AuthenticationServiceApplicationTests {

  @Test
  void contextLoads() {
  }
}
