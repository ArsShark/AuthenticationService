package com.grechanikovars.authenticationservice.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Raised when a refresh token cannot be exchanged: it is not a valid refresh token (garbage, a
 * wrong signature, expired, an access token) or it is not valid any more (used, revoked,
 * unknown, or its account is gone).
 *
 * <p>It is an {@link AuthenticationException}, so the error handler answers it like any other
 * failed authentication: a 401 with a constant detail. The message is for the code only and
 * never reaches the client. It is the same for every cause on purpose, so the answer does not
 * tell a client which of the cases it hit, and it never holds a token.
 */
public class InvalidRefreshTokenException extends AuthenticationException {

  /** The message of the exception, the same for every refused refresh token. */
  public static final String MESSAGE = "Invalid refresh token";

  public InvalidRefreshTokenException() {
    super(MESSAGE);
  }
}
