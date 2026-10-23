package com.grechanikovars.authenticationservice.dto.request;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Checks the validation rules of {@link LoginRequest} with a real bean validator. Only the shape
 * is checked: a weak password or a login that is not an email is a failed login, not a bad
 * request.
 */
class LoginRequestTest {

  private static final String LOGIN = "alice@example.com";
  private static final String PASSWORD = "s3cret-passw0rd";

  private static ValidatorFactory factory;
  private static Validator validator;

  @BeforeAll
  static void createValidator() {
    // The parameter interpolator needs no Jakarta EL implementation on the test classpath.
    factory = Validation.byDefaultProvider()
        .configure()
        .messageInterpolator(new ParameterMessageInterpolator())
        .buildValidatorFactory();
    validator = factory.getValidator();
  }

  @AfterAll
  static void closeValidatorFactory() {
    factory.close();
  }

  @Test
  void validRequestHasNoViolations() {
    assertTrue(validator.validate(new LoginRequest(LOGIN, PASSWORD)).isEmpty());
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   ", "\t"})
  void blankLoginIsRejected(String login) {
    assertEquals(Set.of("login"), violatedProperties(login, PASSWORD));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   ", "\t"})
  void blankPasswordIsRejected(String password) {
    assertEquals(Set.of("password"), violatedProperties(LOGIN, password));
  }

  @Test
  void sizeLimitsAreInclusive() {
    assertAll(
        () -> assertTrue(violatedProperties("a".repeat(255), PASSWORD).isEmpty()),
        () -> assertEquals(Set.of("login"), violatedProperties("a".repeat(256), PASSWORD)),
        () -> assertTrue(violatedProperties(LOGIN, "p".repeat(1024)).isEmpty()),
        () -> assertEquals(Set.of("password"), violatedProperties(LOGIN, "p".repeat(1025))));
  }

  /** The policy of registration does not apply: a weak password is just a wrong one. */
  @Test
  void aWeakPasswordAndALoginThatIsNotAnEmailAreNotMalformed() {
    assertTrue(violatedProperties("not-an-email", "x").isEmpty());
  }

  @Test
  void toStringPrintsNoValue() {
    String text = new LoginRequest(LOGIN, PASSWORD).toString();

    assertAll(
        () -> assertFalse(text.contains(LOGIN)),
        () -> assertFalse(text.contains(PASSWORD)));
  }

  private static Set<String> violatedProperties(String login, String password) {
    return validator.validate(new LoginRequest(login, password)).stream()
        .map(violation -> violation.getPropertyPath().toString())
        .collect(Collectors.toCollection(TreeSet::new));
  }
}
