package com.grechanikovars.authenticationservice.exception;

import org.hibernate.exception.ConstraintViolationException;

/**
 * Finds out which database constraint an exception violated.
 *
 * <p>The name comes from the Hibernate exception in the cause chain, so it does not depend on the
 * language of the messages of the database server. It is used by the error handler of the web
 * layer and by the code that runs at startup.
 */
public final class ViolatedConstraint {

  /** The UNIQUE constraint on {@code credentials.login}. */
  public static final String UNIQUE_LOGIN = "uq_credentials_login";

  /** The UNIQUE constraint on {@code credentials.user_id}. */
  public static final String UNIQUE_USER_ID = "uq_credentials_user_id";

  private static final int MAX_CAUSE_DEPTH = 10;

  private ViolatedConstraint() {
  }

  /**
   * Walks the cause chain for the Hibernate exception that carries the constraint name.
   *
   * @param throwable the exception thrown by Spring Data, may be {@code null}
   * @return the name of the violated constraint, or {@code null} if the chain has none
   */
  public static String nameOf(Throwable throwable) {
    Throwable cause = throwable;
    for (int depth = 0; cause != null && depth < MAX_CAUSE_DEPTH; depth++) {
      if (cause instanceof ConstraintViolationException violation) {
        return violation.getConstraintName();
      }
      cause = cause.getCause();
    }
    return null;
  }
}
