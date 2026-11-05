package com.innowise.authservice.dto.response;


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
