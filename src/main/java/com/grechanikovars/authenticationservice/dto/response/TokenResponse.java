package com.grechanikovars.authenticationservice.dto.response;

import com.grechanikovars.authenticationservice.service.IssuedToken;
import com.grechanikovars.authenticationservice.service.TokenPair;
import java.time.Duration;

/**
 * The answer to a login or a refresh: the two tokens and what a client needs to use them.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print both tokens.
 *
 * @param accessToken the token that goes into the {@code Authorization: Bearer} header
 * @param refreshToken the token that is exchanged for the next pair
 * @param tokenType how the access token is sent; always {@value #BEARER}
 * @param expiresIn the lifetime of the access token in seconds
 */
public record TokenResponse(
    String accessToken, String refreshToken, String tokenType, long expiresIn) {

  /** The only token type of the service (RFC 6750). */
  public static final String BEARER = "Bearer";

  /**
   * Builds the answer from a freshly issued pair.
   *
   * @param pair the access token and the refresh token
   * @return the response; the lifetime is the distance between the issue and the expiry of the
   *     access token
   */
  public static TokenResponse from(TokenPair pair) {
    IssuedToken access = pair.access();
    long expiresIn = Duration.between(access.issuedAt(), access.expiresAt()).toSeconds();
    return new TokenResponse(access.value(), pair.refresh().value(), BEARER, expiresIn);
  }

  /**
   * Describes the response without the tokens.
   *
   * @return the type and the lifetime, and a mask in place of each token
   */
  @Override
  public String toString() {
    return String.format(
        "TokenResponse[accessToken=***, refreshToken=***, tokenType=%s, expiresIn=%d]",
        tokenType, expiresIn);
  }
}
