package com.innowise.authservice.service;

import com.innowise.authservice.client.InternalUserRequest;
import com.innowise.authservice.client.InternalUserResponse;
import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.LoginAlreadyExistsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Registers a user: creates the profile in the User Service, then saves the account here.
 *
 * <ol>
 *   <li>The profile is created with {@code POST /internal/users}. A taken email stops the flow
 *       here, with nothing to undo.
 *   <li>The account is saved by {@link CredentialService#register}, in its own short
 *       transaction, with the email exactly as the User Service stored it and the id of the
 *       profile.
 *   <li>If the account cannot be saved (the login is taken, the database fails), the profile is
 *       deleted again before the caller gets the error, so no profile without an account is left
 *       behind. The original error is the one the caller sees, whatever happens to the deletion.
 * </ol>
 *
 * <p>This class has no {@code @Transactional} on purpose: it calls another service over HTTP, and
 * a transaction around that call would hold a pooled database connection for as long as the
 * User Service takes to answer. The account is saved in the transaction of
 * {@code CredentialService}, which is already committed or rolled back when control comes back
 * here, so "the account was not saved" is certain when the profile is deleted.
 *
 * <p>A crash of this service between the two steps cannot be undone by this code and leaves a
 * profile without an account (a known limit, described in the README). The password and the email
 * are never logged: only the id of the profile.
 */
@Service
public class RegistrationService {

  private static final Logger LOGGER = LoggerFactory.getLogger(RegistrationService.class);

  private final UserServiceClient users;
  private final CredentialService credentials;

  public RegistrationService(UserServiceClient users, CredentialService credentials) {
    this.users = users;
    this.credentials = credentials;
  }

  /**
   * Registers a user.
   *
   * @param request the validated data of the registration
   * @return the new profile
   * @throws EmailAlreadyRegisteredException if the email is taken, in the User Service or here
   * @throws com.innowise.authservice.exception.UserServiceTimeoutException if the User Service
   *     did not answer in time
   * @throws com.innowise.authservice.exception.UserServiceUnavailableException if the User
   *     Service could not be reached or answered unexpectedly
   */
  public RegisterResponse register(RegisterRequest request) {
    InternalUserResponse user = users.create(new InternalUserRequest(
        request.name(), request.surname(), request.birthDate(), request.email()));
    try {
      credentials.register(user.email(), request.password(), user.id());
    } catch (LoginAlreadyExistsException e) {
      undo(user.id(), e);
      throw new EmailAlreadyRegisteredException();
    } catch (RuntimeException e) {
      undo(user.id(), e);
      throw e;
    }
    LOGGER.info("User {} registered", user.id());
    return new RegisterResponse(
        user.id(), user.name(), user.surname(), user.birthDate(), user.email());
  }

  /**
   * Deletes the profile of a registration that failed. A failed deletion is logged with the id
   * and does not hide the original error.
   */
  private void undo(Long userId, RuntimeException cause) {
    LOGGER.warn("Registration of user {} failed ({}), undoing it", userId,
        cause.getClass().getSimpleName());
    try {
      users.delete(userId);
    } catch (RuntimeException e) {
      LOGGER.error("Undoing the registration of user {} is incomplete: the profile must be "
          + "removed by hand ({})", userId, e.getClass().getSimpleName());
    }
  }
}
