package com.grechanikovars.authenticationservice.exception;

/**
 * Thrown when the user profile already has an account: one profile has at most one account.
 *
 * <p>The message holds no login or user id, because messages end up in logs and responses.
 */
public class UserCredentialAlreadyExistsException extends RuntimeException {

  public UserCredentialAlreadyExistsException() {
    super("This user already has an account");
  }
}
