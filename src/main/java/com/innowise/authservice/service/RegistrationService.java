package com.innowise.authservice.service;

import com.innowise.authservice.client.InternalUserRequest;
import com.innowise.authservice.client.InternalUserResponse;
import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.LoginAlreadyExistsException;
import com.innowise.authservice.exception.UserServiceCallException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Registers a user: creates the profile in the User Service, then saves the account here.
 *
 * <ol>
 *   <li>The profile is created with {@code POST /internal/users}, together with a registration id:
 *       a random UUID that this class chooses for every attempt. A taken email stops the flow
 *       here, with nothing to undo. If the creation fails in a way that may have created the
 *       profile all the same (the answer is lost: a timeout, a broken connection, a 5xx, a body
 *       without an id), the profile is deleted by the registration id, because without an answer
 *       its own id is not known. A failure that cannot have created it (the connection could not
 *       be opened, a 4xx) needs no deletion.
 *   <li>The account is saved by {@link CredentialService#register}, in its own short
 *       transaction, with the email exactly as the User Service stored it and the id of the
 *       profile.
 *   <li>If the account cannot be saved (the login is taken, the database fails), the profile is
 *       deleted again by its registration id before the caller gets the error, so no profile
 *       without an account is left behind. A failed deletion is repeated, see
 *       {@link ProfileRemover}. The original error is the one the caller sees, whatever happens
 *       to the deletion.
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
 * are never logged: only the registration id, which is random and means nothing outside this
 * flow, and the id of the profile when it is known.
 */
@Service
public class RegistrationService {

  private static final Logger LOGGER = LoggerFactory.getLogger(RegistrationService.class);

  private final UserServiceClient users;
  private final CredentialService credentials;
  private final ProfileRemover profileRemover;

  public RegistrationService(UserServiceClient users, CredentialService credentials,
      ProfileRemover profileRemover) {
    this.users = users;
    this.credentials = credentials;
    this.profileRemover = profileRemover;
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
    UUID registrationId = UUID.randomUUID();
    InternalUserResponse user;
    try {
      user = users.create(new InternalUserRequest(
          request.name(), request.surname(), request.birthDate(), request.email()),
          registrationId);
    } catch (UserServiceCallException e) {
      if (e.isOutcomeUnknown()) {
        undo(registrationId, e);
      }
      throw e;
    }
    try {
      credentials.register(user.email(), request.password(), user.id());
    } catch (LoginAlreadyExistsException e) {
      undo(registrationId, e);
      throw new EmailAlreadyRegisteredException();
    } catch (RuntimeException e) {
      undo(registrationId, e);
      throw e;
    }
    LOGGER.info("User {} registered", user.id());
    return new RegisterResponse(
        user.id(), user.name(), user.surname(), user.birthDate(), user.email());
  }

  /**
   * Deletes the profile of a registration that failed, by the registration id; the remover
   * repeats a failed deletion and never throws, so the original error is the one that is thrown.
   */
  private void undo(UUID registrationId, RuntimeException cause) {
    LOGGER.warn("Registration {} failed ({}), undoing it", registrationId,
        cause.getClass().getSimpleName());
    profileRemover.remove(registrationId);
  }
}
