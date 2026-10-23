package com.grechanikovars.authenticationservice.service;

import java.time.Instant;
import java.util.UUID;

/**
 * A token that was just signed, with the values that the caller needs to store or to return.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the token.
 *
 * @param value the compact serialized token, the string a client sends back
 * @param jti the id of the token (the {@code jti} claim); a refresh token is stored by it
 * @param issuedAt the {@code iat} claim, in whole seconds
 * @param expiresAt the {@code exp} claim, in whole seconds
 */
public record IssuedToken(String value, UUID jti, Instant issuedAt, Instant expiresAt) {

  /**
   * Describes the token without its value.
   *
   * @return the id and the times of the token, and a mask in place of the value
   */
  @Override
  public String toString() {
    return String.format("IssuedToken[jti=%s, issuedAt=%s, expiresAt=%s, value=***]",
        jti, issuedAt, expiresAt);
  }
}
