package com.innowise.authservice.exception;

/**
 * Thrown when a registration uses an email that already belongs to a user.
 *
 * <p>The message holds no email, because messages end up in logs and responses.
 */
public class EmailAlreadyRegisteredException extends RuntimeException {

  /** The detail sent to the client. */
  public static final String MESSAGE = "An account with this email already exists";

  public EmailAlreadyRegisteredException() {
    super(MESSAGE);
  }
}
