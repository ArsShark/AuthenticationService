package com.grechanikovars.authenticationservice.service;

import com.grechanikovars.authenticationservice.entity.Role;
import java.time.Instant;

/**
 * What a valid access token says about its owner.
 *
 * <p>{@link #toString()} is overridden on purpose: the email is personal data.
 *
 * @param credentialId the id of the account in this service (the {@code sub} claim)
 * @param userId the id of the profile in User Service, or {@code null} for an admin that has none
 * @param role the role of the account
 * @param email the login of the account, which is its email
 * @param expiresAt the moment the token expires
 */
public record AccessTokenClaims(
    long credentialId, Long userId, Role role, String email, Instant expiresAt) {

  /**
   * Describes the claims without the email.
   *
   * @return the ids, the role and the expiry, and a mask in place of the email
   */
  @Override
  public String toString() {
    return String.format(
        "AccessTokenClaims[credentialId=%d, userId=%s, role=%s, email=***, expiresAt=%s]",
        credentialId, userId, role, expiresAt);
  }
}
