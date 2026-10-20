package com.grechanikovars.authenticationservice.exception;

/**
 * Thrown when a call to an internal endpoint has no internal key or a wrong one.
 *
 * <p>The message is the same for both cases on purpose: the caller learns nothing about the key.
 */
public class InvalidInternalKeyException extends RuntimeException {

  public InvalidInternalKeyException() {
    super("Missing or invalid internal key");
  }
}
