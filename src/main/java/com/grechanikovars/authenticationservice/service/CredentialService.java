package com.grechanikovars.authenticationservice.service;

import com.grechanikovars.authenticationservice.dto.response.CredentialResponse;
import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.exception.LoginAlreadyExistsException;
import com.grechanikovars.authenticationservice.exception.UserCredentialAlreadyExistsException;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import java.util.Locale;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates and looks up accounts (login, password hash, role).
 *
 * <p>Neither the login, nor the password, nor the hash is ever logged: only ids.
 */
@Service
@Transactional(readOnly = true)
public class CredentialService {

  private static final Logger LOGGER = LogManager.getLogger(CredentialService.class);

  private final CredentialRepository credentialRepository;
  private final PasswordEncoder passwordEncoder;

  public CredentialService(CredentialRepository credentialRepository,
      PasswordEncoder passwordEncoder) {
    this.credentialRepository = credentialRepository;
    this.passwordEncoder = passwordEncoder;
  }

  /**
   * Registers a new account with the role {@link Role#USER}.
   *
   * <p>The login is stripped and lowercased, like the email in User Service. The checks run
   * before the password is hashed, so a duplicate is rejected without the cost of BCrypt. They
   * are only a fast path: two parallel requests can both pass them, and then the UNIQUE
   * constraints of the database reject one of them with a {@link DataIntegrityViolationException},
   * which is not caught here.
   *
   * @param login the email of the user
   * @param password the raw password; it is hashed and never stored or logged
   * @param userId the id of the profile in User Service
   * @return the public view of the new account
   * @throws LoginAlreadyExistsException if the login is taken
   * @throws UserCredentialAlreadyExistsException if the profile already has an account
   */
  @Transactional
  public CredentialResponse register(String login, String password, Long userId) {
    String normalizedLogin = normalize(login);
    if (credentialRepository.existsByLogin(normalizedLogin)) {
      throw new LoginAlreadyExistsException();
    }
    if (credentialRepository.existsByUserId(userId)) {
      throw new UserCredentialAlreadyExistsException();
    }
    Credential credential = new Credential(
        normalizedLogin, passwordEncoder.encode(password), Role.USER, userId);
    Credential saved = credentialRepository.saveAndFlush(credential);
    LOGGER.info("Credential {} registered for user {}", saved.getId(), saved.getUserId());
    return CredentialResponse.from(saved);
  }

  /**
   * Creates the account of an admin, unless the login already exists. An admin has the role
   * {@link Role#ADMIN} and no user profile.
   *
   * <p>An existing account is never changed: the password of an existing admin is not overwritten,
   * and an account of a user is not promoted. If two instances of the service start at the same
   * time, the UNIQUE constraint rejects one insert with a {@link DataIntegrityViolationException},
   * which is not caught here: the transaction is already marked for rollback, so the caller
   * decides what it means.
   *
   * @param login the login of the admin, normalized like every login
   * @param password the raw password; it is hashed and never stored or logged
   * @return what happened, see {@link AdminResult}
   */
  @Transactional
  public AdminResult createAdminIfAbsent(String login, String password) {
    String normalizedLogin = normalize(login);
    Optional<Credential> existing = credentialRepository.findByLogin(normalizedLogin);
    if (existing.isPresent()) {
      return existing.get().getRole() == Role.ADMIN
          ? AdminResult.ADMIN_EXISTS
          : AdminResult.LOGIN_TAKEN_BY_USER;
    }
    Credential credential = new Credential(
        normalizedLogin, passwordEncoder.encode(password), Role.ADMIN, null);
    Credential saved = credentialRepository.saveAndFlush(credential);
    LOGGER.info("Admin credential {} created", saved.getId());
    return AdminResult.CREATED;
  }

  /** The outcome of {@link #createAdminIfAbsent(String, String)}. */
  public enum AdminResult {

    /** A new admin account was created. */
    CREATED,

    /** An admin account with this login already exists; nothing was changed. */
    ADMIN_EXISTS,

    /** The login belongs to an account with the role USER; nothing was changed. */
    LOGIN_TAKEN_BY_USER
  }

  /**
   * Strips a login and makes it lowercase. Registration stores logins in this form and the login
   * of the authentication service looks them up in it, so both must use this one method.
   *
   * @param login a raw login, not {@code null}
   * @return the form in which logins are stored
   */
  static String normalize(String login) {
    return login.strip().toLowerCase(Locale.ROOT);
  }
}
