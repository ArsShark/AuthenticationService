package com.grechanikovars.authenticationservice.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Raised when a login fails: the login is unknown or the password is wrong.
 *
 * <p>It is an {@link AuthenticationException}, so the error handler answers it like any other
 * failed authentication: a 401 with a constant detail. The message is for the code only and never
 * reaches the client. It is the same for both causes on purpose, and it holds neither the login
 * nor the password.
 */
public class InvalidCredentialsException extends AuthenticationException {

  /** The message of the exception, the same for every failed login. */
  public static final String MESSAGE = "Invalid login or password";

  public InvalidCredentialsException() {
    super(MESSAGE);
  }
}
