package com.innowise.authservice.exception;

/**
 * Thrown when the User Service does not connect or answer in time. The client gets a 504.
 *
 * <p>The message is constant, for the same reason as in {@link UserServiceUnavailableException}.
 */
public class UserServiceTimeoutException extends RuntimeException {

  /** The detail sent to the client. */
  public static final String MESSAGE = "The user service did not answer in time";

  public UserServiceTimeoutException() {
    super(MESSAGE);
  }
}
