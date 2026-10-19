package com.grechanikovars.authenticationservice.exception;

/**
 * Thrown when an account with the same login already exists.
 *
 * <p>The message holds no login, because messages end up in logs and responses.
 */
public class LoginAlreadyExistsException extends RuntimeException {

  public LoginAlreadyExistsException() {
    super("An account with this login already exists");
  }
}
