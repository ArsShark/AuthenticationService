package com.grechanikovars.authenticationservice.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Tests {@link ViolatedConstraint}. The Hibernate exception is a mock, so the tests do not depend
 * on its constructors; the real names are proved by the HTTP integration tests.
 */
class ViolatedConstraintTest {

  @Test
  void findsTheNameDeepInTheCauseChain() {
    Exception exception = new DataIntegrityViolationException("outer",
        new RuntimeException("middle", hibernateException("uq_credentials_login")));

    assertEquals("uq_credentials_login", ViolatedConstraint.nameOf(exception));
  }

  @Test
  void findsTheNameWhenTheExceptionIsTheHibernateOne() {
    assertEquals("uq_credentials_user_id",
        ViolatedConstraint.nameOf(hibernateException("uq_credentials_user_id")));
  }

  @Test
  void returnsNullWithoutAHibernateExceptionInTheChain() {
    Exception exception =
        new DataIntegrityViolationException("outer", new IllegalStateException("inner"));

    assertNull(ViolatedConstraint.nameOf(exception));
  }

  @Test
  void returnsNullForNull() {
    assertNull(ViolatedConstraint.nameOf(null));
  }

  private static ConstraintViolationException hibernateException(String constraint) {
    ConstraintViolationException exception = mock(ConstraintViolationException.class);
    when(exception.getConstraintName()).thenReturn(constraint);
    return exception;
  }
}
