package com.innowise.authservice.mapper;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.innowise.authservice.dto.response.TokenResponse;
import com.innowise.authservice.service.IssuedToken;
import com.innowise.authservice.service.TokenPair;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Checks how a pair of tokens becomes the body of a login or a refresh answer.
 */
class TokenMapperTest {

  private static final Instant NOW = Instant.parse("2026-10-19T10:00:00Z");

  private final TokenMapper mapper = new TokenMapperImpl();

  @Test
  void carriesBothTokensTheTypeAndTheLifetimeOfTheAccessTokenInSeconds() {
    TokenPair pair = new TokenPair(
        new IssuedToken("access-token-value", UUID.randomUUID(), NOW,
            NOW.plus(Duration.ofMinutes(15))),
        new IssuedToken("refresh-token-value", UUID.randomUUID(), NOW,
            NOW.plus(Duration.ofDays(7))));

    TokenResponse response = mapper.toResponse(pair);

    assertAll(
        () -> assertEquals("access-token-value", response.accessToken()),
        () -> assertEquals("refresh-token-value", response.refreshToken()),
        () -> assertEquals("Bearer", response.tokenType()),
        () -> assertEquals(900L, response.expiresIn()));
  }

  /** The lifetime is the one of the access token, never the one of the refresh token. */
  @Test
  void theLifetimeIsNotTheOneOfTheRefreshToken() {
    TokenPair pair = new TokenPair(
        new IssuedToken("a", UUID.randomUUID(), NOW, NOW.plusSeconds(60)),
        new IssuedToken("r", UUID.randomUUID(), NOW, NOW.plusSeconds(3600)));

    assertEquals(60L, mapper.toResponse(pair).expiresIn());
  }
}
