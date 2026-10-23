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
 * Checks the validation rules of {@link RefreshRequest} with a real bean validator. Only the
 * shape is checked: a text that is not a real token is a failed refresh, not a bad request.
 */
class RefreshRequestTest {

  private static final String TOKEN = "header.payload.signature";

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
    assertTrue(validator.validate(new RefreshRequest(TOKEN)).isEmpty());
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   ", "\t"})
  void blankTokenIsRejected(String token) {
    assertEquals(Set.of("refreshToken"), violatedProperties(token));
  }

  @Test
  void sizeLimitIsInclusive() {
    assertAll(
        () -> assertTrue(violatedProperties("t".repeat(4096)).isEmpty()),
        () -> assertEquals(Set.of("refreshToken"), violatedProperties("t".repeat(4097))));
  }

  @Test
  void toStringPrintsNoValue() {
    assertFalse(new RefreshRequest(TOKEN).toString().contains(TOKEN));
  }

  private static Set<String> violatedProperties(String token) {
    return validator.validate(new RefreshRequest(token)).stream()
        .map(violation -> violation.getPropertyPath().toString())
        .collect(Collectors.toCollection(TreeSet::new));
  }
}
