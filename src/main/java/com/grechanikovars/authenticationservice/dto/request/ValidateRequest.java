package com.grechanikovars.authenticationservice.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * The body of a token validation.
 *
 * <p>Only the shape is checked here. Whether the text is a valid access token is the answer to
 * the request, not a reason to refuse it. The size limit only keeps absurd values away from the
 * parser; a signed token of this service is far shorter.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the token.
 *
 * @param token the access token to check
 */
public record ValidateRequest(@NotBlank @Size(max = 4096) String token) {

  /**
   * Describes the request without its value.
   *
   * @return a fixed text
   */
  @Override
  public String toString() {
    return "ValidateRequest[token=***]";
  }
}
