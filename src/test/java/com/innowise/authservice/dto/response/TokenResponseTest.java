package com.innowise.authservice.dto.response;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Checks the text form of the answer of a login or a refresh. The mapping from a pair of tokens is
 * tested in {@code TokenMapperTest}.
 */
class TokenResponseTest {

  @Test
  void toStringPrintsNeitherToken() {
    String text = new TokenResponse(
        "access-token-value", "refresh-token-value", "Bearer", 900L).toString();

    assertAll(
        () -> assertFalse(text.contains("access-token-value")),
        () -> assertFalse(text.contains("refresh-token-value")),
        () -> assertTrue(text.contains("expiresIn=900")));
  }
}
