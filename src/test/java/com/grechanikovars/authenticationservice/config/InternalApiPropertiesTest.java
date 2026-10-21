package com.grechanikovars.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Checks that the internal key does not leak through the settings object. That the application
 * cannot start without the key is checked by the constructor of the key filter.
 */
class InternalApiPropertiesTest {

  @Test
  void propertiesDoNotPrintTheKey() {
    String text = new InternalApiProperties("secret-key-123").toString();

    assertAll(
        () -> assertFalse(text.contains("secret-key-123")),
        () -> assertTrue(text.startsWith("InternalApiProperties")));
  }
}
