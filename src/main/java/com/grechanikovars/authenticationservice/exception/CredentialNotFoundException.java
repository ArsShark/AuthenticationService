package com.grechanikovars.authenticationservice.exception;

/**
 * Thrown when no account of a user exists for the given profile id.
 *
 * <p>The message holds no id, because messages end up in logs and responses.
 */
public class CredentialNotFoundException extends RuntimeException {

  /** The message, also the detail for the client. */
  public static final String MESSAGE = "No account exists for this user";

  public CredentialNotFoundException() {
    super(MESSAGE);
  }
}
