package com.grechanikovars.authenticationservice.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * The body of a refresh.
 *
 * <p>Only the shape is checked here. Whether the text is a real refresh token is decided by the
 * service, and a bad one is a failed refresh (401), not a malformed request. The size limit only
 * keeps absurd values away from the parser; a signed token of this service is far shorter.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the token.
 *
 * @param refreshToken the refresh token that was returned by the login or by the last refresh
 */
public record RefreshRequest(@NotBlank @Size(max = 4096) String refreshToken) {

  /**
   * Describes the request without its value.
   *
   * @return a fixed text
   */
  @Override
  public String toString() {
    return "RefreshRequest[refreshToken=***]";
  }
}
