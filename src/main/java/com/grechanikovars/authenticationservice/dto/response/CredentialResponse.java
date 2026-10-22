package com.grechanikovars.authenticationservice.dto.response;

import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import java.time.Instant;

/**
 * The public view of an account.
 *
 * <p>It has no password hash on purpose: the hash never leaves the service.
 *
 * @param id the id of the account
 * @param login the normalized login (the email)
 * @param role the role of the account
 * @param userId the id of the profile in User Service, or {@code null} for an admin without one
 * @param createdAt the moment the account was created
 */
public record CredentialResponse(Long id, String login, Role role, Long userId,
    Instant createdAt) {

  /**
   * Creates the response from an account.
   *
   * @param credential a saved account
   * @return the public view of the account
   */
  public static CredentialResponse from(Credential credential) {
    return new CredentialResponse(credential.getId(), credential.getLogin(),
        credential.getRole(), credential.getUserId(), credential.getCreatedAt());
  }
}
