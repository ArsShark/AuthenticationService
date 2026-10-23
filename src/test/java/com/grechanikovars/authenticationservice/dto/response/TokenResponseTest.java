package com.grechanikovars.authenticationservice.dto.response;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.grechanikovars.authenticationservice.service.IssuedToken;
import com.grechanikovars.authenticationservice.service.TokenPair;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Checks how a pair of tokens becomes the body of a login or a refresh answer.
 */
class TokenResponseTest {

  private static final Instant NOW = Instant.parse("2026-10-19T10:00:00Z");

  private final TokenPair pair = new TokenPair(
      new IssuedToken("access-token-value", UUID.randomUUID(), NOW,
          NOW.plus(Duration.ofMinutes(15))),
      new IssuedToken("refresh-token-value", UUID.randomUUID(), NOW,
          NOW.plus(Duration.ofDays(7))));

  @Test
  void carriesBothTokensTheTypeAndTheLifetimeOfTheAccessTokenInSeconds() {
    TokenResponse response = TokenResponse.from(pair);

    assertAll(
        () -> assertEquals("access-token-value", response.accessToken()),
        () -> assertEquals("refresh-token-value", response.refreshToken()),
        () -> assertEquals("Bearer", response.tokenType()),
        () -> assertEquals(900L, response.expiresIn()));
  }

  @Test
  void toStringPrintsNeitherToken() {
    String text = TokenResponse.from(pair).toString();

    assertAll(
        () -> assertFalse(text.contains("access-token-value")),
        () -> assertFalse(text.contains("refresh-token-value")),
        () -> assertTrue(text.contains("expiresIn=900")));
  }
}
