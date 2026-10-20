package com.grechanikovars.authenticationservice.config;

import com.grechanikovars.authenticationservice.dto.request.CredentialRequest;
import com.grechanikovars.authenticationservice.exception.ViolatedConstraint;
import com.grechanikovars.authenticationservice.service.CredentialService;
import com.grechanikovars.authenticationservice.service.CredentialService.AdminResult;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

/**
 * Creates the first admin at startup, so a fresh environment (Docker Compose, Kubernetes) needs
 * no manual step. Registration through the API always creates the role USER, so there is no
 * other way to get an admin.
 *
 * <p>The behavior depends on the environment variables {@code ADMIN_LOGIN} and
 * {@code ADMIN_PASSWORD}:
 * <ul>
 *   <li>both empty: nothing happens;</li>
 *   <li>only one set, or a value that breaks the rules of the registration request: the
 *       application does not start;</li>
 *   <li>both set: the admin is created if the login does not exist yet. An existing account is
 *       never changed, so a changed password in the environment does not overwrite the old
 *       one.</li>
 * </ul>
 *
 * <p>The login and the password follow the same rules as in {@link CredentialRequest}: the
 * constraints of that class are the single source. Neither the login nor the password is ever
 * logged or put into an error message.
 */
@Component
@EnableConfigurationProperties(AdminProperties.class)
public class AdminInitializer implements ApplicationRunner {

  private static final Logger LOGGER = LogManager.getLogger(AdminInitializer.class);

  private final AdminProperties properties;
  private final CredentialService credentialService;
  private final Validator validator;

  public AdminInitializer(AdminProperties properties, CredentialService credentialService,
      Validator validator) {
    this.properties = properties;
    this.credentialService = credentialService;
    this.validator = validator;
  }

  @Override
  public void run(ApplicationArguments args) {
    String login = properties.login();
    String password = properties.password();
    boolean loginSet = hasValue(login);
    boolean passwordSet = hasValue(password);
    if (!loginSet && !passwordSet) {
      LOGGER.info("The first admin is not configured: ADMIN_LOGIN and ADMIN_PASSWORD are empty");
      return;
    }
    if (loginSet != passwordSet) {
      throw new IllegalStateException("Set both ADMIN_LOGIN and ADMIN_PASSWORD, or neither");
    }
    requireValid("login", "ADMIN_LOGIN", login);
    requireValid("password", "ADMIN_PASSWORD", password);
    createAdmin(login, password);
  }

  private void createAdmin(String login, String password) {
    try {
      AdminResult result = credentialService.createAdminIfAbsent(login, password);
      switch (result) {
        case CREATED -> LOGGER.info("The first admin was created");
        case ADMIN_EXISTS -> LOGGER.info("The first admin already exists, nothing to do");
        case LOGIN_TAKEN_BY_USER -> LOGGER.warn(
            "ADMIN_LOGIN belongs to an account with the role USER: no admin was created");
      }
    } catch (DataIntegrityViolationException ex) {
      // Another instance of the service created the same admin a moment earlier.
      if (!ViolatedConstraint.UNIQUE_LOGIN.equals(ViolatedConstraint.nameOf(ex))) {
        throw ex;
      }
      LOGGER.info("The first admin was created by another instance of the service");
    }
  }

  /**
   * Checks a value with the constraints of the same property of {@link CredentialRequest}. The
   * messages of the constraints never hold the value, so they are safe in an error message.
   */
  private void requireValid(String property, String variable, String value) {
    Set<ConstraintViolation<CredentialRequest>> violations =
        validator.validateValue(CredentialRequest.class, property, value);
    if (!violations.isEmpty()) {
      String reasons = violations.stream()
          .map(ConstraintViolation::getMessage)
          .sorted()
          .collect(Collectors.joining("; "));
      throw new IllegalStateException(String.format("%s is invalid: %s", variable, reasons));
    }
  }

  private static boolean hasValue(String value) {
    return value != null && !value.isEmpty();
  }
}
