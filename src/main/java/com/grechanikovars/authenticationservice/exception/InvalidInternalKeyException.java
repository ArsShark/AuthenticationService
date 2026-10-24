package com.grechanikovars.authenticationservice.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Raised when a call to an internal endpoint carries a wrong internal key.
 *
 * <p>It is an {@link AuthenticationException}, so the error handler answers it like any other
 * failed authentication: a 401 with a constant detail. The message is for the code only and never
 * reaches the client. A call with no key at all is not rejected here; it stays anonymous.
 */
public class InvalidInternalKeyException extends AuthenticationException {

  public InvalidInternalKeyException() {
    super("Invalid internal key");
  }
}
