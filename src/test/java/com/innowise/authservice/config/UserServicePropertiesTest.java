package com.innowise.authservice.config;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Checks that settings which would make the registration hang or fail are refused at startup.
 */
class UserServicePropertiesTest {

  private static final Duration TWO = Duration.ofSeconds(2);

  @Test
  void validSettingsAreAccepted() {
    assertDoesNotThrow(() -> new UserServiceProperties("http://user-service:8082", TWO, TWO));
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "   "})
  void aBlankAddressIsRefused(String baseUri) {
    assertThrows(IllegalArgumentException.class,
        () -> new UserServiceProperties(baseUri, TWO, TWO));
  }

  @Test
  void aMissingAddressIsRefused() {
    assertThrows(IllegalArgumentException.class, () -> new UserServiceProperties(null, TWO, TWO));
  }

  @Test
  void timeoutsThatAreNotPositiveAreRefused() {
    assertAll(
        () -> assertThrows(IllegalArgumentException.class,
            () -> new UserServiceProperties("http://x", Duration.ZERO, TWO)),
        () -> assertThrows(IllegalArgumentException.class,
            () -> new UserServiceProperties("http://x", TWO, Duration.ofSeconds(-1))));
  }
}
