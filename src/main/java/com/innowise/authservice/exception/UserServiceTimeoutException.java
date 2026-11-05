package com.innowise.authservice.exception;

/**
 * Thrown when the User Service does not connect or answer in time. The client gets a 504.
 *
 * <p>The message is constant, for the same reason as in {@link UserServiceUnavailableException}.
 */
public class UserServiceTimeoutException extends UserServiceCallException {

  /** The detail sent to the client. */
  public static final String MESSAGE = "The user service did not answer in time";

  /**
   * Creates the exception.
   *
   * @param outcomeUnknown see {@link UserServiceCallException#isOutcomeUnknown()}; {@code false}
   *     for a timeout of the connection, {@code true} for a timeout of the answer
   */
  public UserServiceTimeoutException(boolean outcomeUnknown) {
    super(MESSAGE, outcomeUnknown);
  }
}
