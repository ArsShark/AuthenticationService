package com.innowise.authservice.exception;

/**
 * A call to the User Service that failed: the base of {@link UserServiceUnavailableException}
 * and {@link UserServiceTimeoutException}.
 *
 * <p>It tells the caller whether the User Service may nevertheless have carried the request out.
 * That matters for a call that changes data: a creation whose answer was lost can have created
 * the profile, and the caller must then undo it. The messages of the subclasses are constant, for
 * the reason given there.
 */
public abstract class UserServiceCallException extends RuntimeException {

  private final boolean outcomeUnknown;

  /**
   * Creates the exception.
   *
   * @param message the constant detail sent to the client
   * @param outcomeUnknown {@code true} if the request may have reached the User Service and been
   *     carried out; {@code false} if it certainly had no effect (the connection could not be
   *     opened, or the User Service rejected the request with a client error)
   */
  protected UserServiceCallException(String message, boolean outcomeUnknown) {
    super(message);
    this.outcomeUnknown = outcomeUnknown;
  }

  /**
   * Tells whether the User Service may have carried the request out although the call failed.
   *
   * @return {@code true} if the effect of the request is unknown
   */
  public boolean isOutcomeUnknown() {
    return outcomeUnknown;
  }
}
