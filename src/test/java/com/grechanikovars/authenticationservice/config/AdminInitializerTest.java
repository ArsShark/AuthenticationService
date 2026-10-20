package com.grechanikovars.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.grechanikovars.authenticationservice.service.CredentialService;
import com.grechanikovars.authenticationservice.service.CredentialService.AdminResult;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.hibernate.exception.ConstraintViolationException;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * Unit tests of {@link AdminInitializer}: the service is a mock, the validator is a real one, so
 * the rules are the ones of the registration request.
 */
@ExtendWith(MockitoExtension.class)
class AdminInitializerTest {

  private static final String LOGIN = "admin@example.com";
  private static final String PASSWORD = "Adm1n-passw0rd";

  private static ValidatorFactory factory;
  private static Validator validator;

  @Mock
  private CredentialService credentialService;

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

  @ParameterizedTest
  @NullAndEmptySource
  void bothEmptyIsSkipped(String empty) {
    run(empty, empty);

    verifyNoInteractions(credentialService);
  }

  @Test
  void onlyTheLoginSetFailsTheStartup() {
    IllegalStateException error = assertThrows(IllegalStateException.class, () -> run(LOGIN, ""));

    assertTrue(error.getMessage().contains("ADMIN_LOGIN and ADMIN_PASSWORD"));
    verifyNoInteractions(credentialService);
  }

  @Test
  void onlyThePasswordSetFailsTheStartup() {
    IllegalStateException error =
        assertThrows(IllegalStateException.class, () -> run(null, PASSWORD));

    assertTrue(error.getMessage().contains("ADMIN_LOGIN and ADMIN_PASSWORD"));
    verifyNoInteractions(credentialService);
  }

  @Test
  void invalidLoginFailsTheStartupWithoutEchoingIt() {
    IllegalStateException error =
        assertThrows(IllegalStateException.class, () -> run("not-an-email", PASSWORD));

    assertAll(
        () -> assertTrue(error.getMessage().contains("ADMIN_LOGIN")),
        () -> assertFalse(error.getMessage().contains("not-an-email")));
    verifyNoInteractions(credentialService);
  }

  @Test
  void invalidPasswordFailsTheStartupWithoutEchoingIt() {
    IllegalStateException error =
        assertThrows(IllegalStateException.class, () -> run(LOGIN, "short"));

    assertAll(
        () -> assertTrue(error.getMessage().contains("ADMIN_PASSWORD")),
        () -> assertFalse(error.getMessage().contains("short")));
    verifyNoInteractions(credentialService);
  }

  @Test
  void validSettingsCreateTheAdmin() {
    when(credentialService.createAdminIfAbsent(LOGIN, PASSWORD)).thenReturn(AdminResult.CREATED);

    run(LOGIN, PASSWORD);

    verify(credentialService).createAdminIfAbsent(LOGIN, PASSWORD);
  }

  @ParameterizedTest
  @EnumSource(AdminResult.class)
  void everyResultLetsTheStartupContinue(AdminResult result) {
    when(credentialService.createAdminIfAbsent(LOGIN, PASSWORD)).thenReturn(result);

    assertDoesNotThrow(() -> run(LOGIN, PASSWORD));
  }

  @Test
  void lostRaceOnTheUniqueLoginIsNotAnError() {
    DataIntegrityViolationException violation = integrityViolation("uq_credentials_login");
    when(credentialService.createAdminIfAbsent(LOGIN, PASSWORD)).thenThrow(violation);

    assertDoesNotThrow(() -> run(LOGIN, PASSWORD));
  }

  @Test
  void otherIntegrityViolationFailsTheStartup() {
    DataIntegrityViolationException violation = integrityViolation("ck_credentials_role");
    when(credentialService.createAdminIfAbsent(LOGIN, PASSWORD)).thenThrow(violation);

    assertThrows(DataIntegrityViolationException.class, () -> run(LOGIN, PASSWORD));
  }

  private void run(String login, String password) {
    new AdminInitializer(new AdminProperties(login, password), credentialService, validator)
        .run(new DefaultApplicationArguments());
  }

  /**
   * Builds the exception before the stubbing that throws it: Mockito does not allow a mock to be
   * stubbed inside the arguments of another stubbing.
   */
  private static DataIntegrityViolationException integrityViolation(String constraint) {
    ConstraintViolationException cause = mock(ConstraintViolationException.class);
    when(cause.getConstraintName()).thenReturn(constraint);
    return new DataIntegrityViolationException("irrelevant", cause);
  }
}
