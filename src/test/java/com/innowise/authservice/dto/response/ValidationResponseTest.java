package com.innowise.authservice.dto.response;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/**
 * Tests the answer for a token that is not valid. The answer for a valid token is built by
 * {@code ValidationMapper} and tested in {@code ValidationMapperTest}. How empty fields are left
 * out of the JSON is proved in {@code AuthControllerTest}, with the real JSON mapper of the
 * application.
 */
class ValidationResponseTest {

  @Test
  void aTokenThatIsNotValidHasNothingButTheFlag() {
    ValidationResponse response = ValidationResponse.invalid();

    assertAll(
        () -> assertFalse(response.valid()),
        () -> assertNull(response.userId()),
        () -> assertNull(response.role()),
        () -> assertNull(response.expiresAt()));
  }
}
