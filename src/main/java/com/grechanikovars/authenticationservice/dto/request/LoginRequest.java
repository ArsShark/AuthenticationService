package com.grechanikovars.authenticationservice.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * The body of a login.
 *
 * <p>Only the shape is checked here. The login is not required to be an email and the password
 * is not checked against the password policy: a wrong or weak password is not a malformed
 * request, it is a failed login and gets the same 401 as any other. The size limits only keep
 * absurd values away from the hash comparison.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the password
 * and the login (an email).
 *
 * @param login the login of the account, which is its email; surrounding spaces and the case are
 *     ignored
 * @param password the raw password
 */
public record LoginRequest(
    @NotBlank @Size(max = 255) String login,
    @NotBlank @Size(max = 1024) String password) {

  /**
   * Describes the request without any of its values.
   *
   * @return a fixed text
   */
  @Override
  public String toString() {
    return "LoginRequest[login=***, password=***]";
  }
}
