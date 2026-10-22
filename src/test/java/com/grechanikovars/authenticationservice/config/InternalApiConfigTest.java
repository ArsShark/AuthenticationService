package com.grechanikovars.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

/**
 * Checks that the application cannot start with an open internal endpoint, and that the key does
 * not leak through the settings object.
 */
class InternalApiConfigTest {

  @Test
  void startupFailsWithoutTheKey() {
    InternalApiConfig config = new InternalApiConfig(new InternalApiProperties(""));

    assertThrows(IllegalArgumentException.class,
        () -> config.addInterceptors(new InterceptorRegistry()));
  }

  @Test
  void propertiesDoNotPrintTheKey() {
    String text = new InternalApiProperties("secret-key-123").toString();

    assertAll(
        () -> assertFalse(text.contains("secret-key-123")),
        () -> assertTrue(text.startsWith("InternalApiProperties")));
  }
}
