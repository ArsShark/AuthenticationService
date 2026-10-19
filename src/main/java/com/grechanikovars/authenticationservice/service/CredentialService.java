package com.grechanikovars.authenticationservice.service;

import com.grechanikovars.authenticationservice.dto.response.CredentialResponse;
import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.exception.LoginAlreadyExistsException;
import com.grechanikovars.authenticationservice.exception.UserCredentialAlreadyExistsException;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import java.util.Locale;
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

  private static String normalize(String login) {
    return login.strip().toLowerCase(Locale.ROOT);
  }
}
