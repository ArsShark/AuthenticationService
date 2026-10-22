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
import java.util.stream.Stream;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Checks the validation rules of {@link CredentialRequest} with a real bean validator.
 */
class CredentialRequestTest {

  private static final String LOGIN = "alice@example.com";
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final Long USER_ID = 7L;

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
    assertTrue(validator.validate(new CredentialRequest(LOGIN, PASSWORD, USER_ID)).isEmpty());
  }

  @ParameterizedTest
  @MethodSource("invalidLogins")
  void invalidLoginIsRejected(String login) {
    assertEquals(Set.of("login"), violatedProperties(login, PASSWORD, USER_ID));
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(longs = {0, -1})
  void invalidUserIdIsRejected(Long userId) {
    assertEquals(Set.of("userId"), violatedProperties(LOGIN, PASSWORD, userId));
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"short", "        "})
  void invalidPasswordIsRejected(String password) {
    assertEquals(Set.of("password"), violatedProperties(LOGIN, password, USER_ID));
  }

  @Test
  void passwordLongerThanSeventyTwoBytesIsRejected() {
    assertEquals(Set.of("password"), violatedProperties(LOGIN, "a".repeat(73), USER_ID));
  }

  @Test
  void everyInvalidFieldIsReported() {
    assertEquals(Set.of("login", "password", "userId"),
        violatedProperties("not-an-email", "short", 0L));
  }

  @Test
  void toStringHidesThePasswordAndTheLogin() {
    String text = new CredentialRequest(LOGIN, PASSWORD, USER_ID).toString();

    assertAll(
        () -> assertFalse(text.contains(PASSWORD)),
        () -> assertFalse(text.contains(LOGIN)),
        () -> assertTrue(text.contains("userId=7")));
  }

  static Stream<String> invalidLogins() {
    return Stream.of(null, "", "   ", "not-an-email", "a".repeat(250).concat("@x.com"));
  }

  private static Set<String> violatedProperties(String login, String password, Long userId) {
    return validator.validate(new CredentialRequest(login, password, userId)).stream()
        .map(violation -> violation.getPropertyPath().toString())
        .collect(Collectors.toCollection(TreeSet::new));
  }
}
