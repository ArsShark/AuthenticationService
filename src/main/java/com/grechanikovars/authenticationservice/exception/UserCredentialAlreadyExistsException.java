package com.grechanikovars.authenticationservice.exception;

/**
 * Thrown when the user profile already has an account: one profile has at most one account.
 *
 * <p>The message holds no login or user id, because messages end up in logs and responses.
 */
public class UserCredentialAlreadyExistsException extends RuntimeException {

  /** The message, also used by the error handler for a lost race on the UNIQUE constraint. */
  public static final String MESSAGE = "This user already has an account";

  public UserCredentialAlreadyExistsException() {
    super(MESSAGE);
  }
}
