package com.innowise.authservice.exception;

/**
 * Thrown when the User Service cannot be reached or answers with something unexpected (an error
 * status, a body that cannot be read). The client gets a 502.
 *
 * <p>The message is constant: the real cause (an address, a status, a body) goes to the log, never
 * to the response.
 */
public class UserServiceUnavailableException extends RuntimeException {

  /** The detail sent to the client. */
  public static final String MESSAGE = "The user service is not available";

  public UserServiceUnavailableException() {
    super(MESSAGE);
  }
}
