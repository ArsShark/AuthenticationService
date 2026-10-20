package com.grechanikovars.authenticationservice.exception;

/**
 * Thrown when an account with the same login already exists.
 *
 * <p>The message holds no login, because messages end up in logs and responses.
 */
public class LoginAlreadyExistsException extends RuntimeException {

  /** The message, also used by the error handler for a lost race on the UNIQUE constraint. */
  public static final String MESSAGE = "An account with this login already exists";

  public LoginAlreadyExistsException() {
    super(MESSAGE);
  }
}
