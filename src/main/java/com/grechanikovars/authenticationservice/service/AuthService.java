package com.grechanikovars.authenticationservice.service;

import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.exception.InvalidCredentialsException;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import com.grechanikovars.authenticationservice.validation.PasswordPolicy;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Logs users in.
 *
 * <p>The class has no {@code @Transactional}, on purpose. A login checks the password with
 * BCrypt, which takes tens of milliseconds, and a transaction around that would hold a database
 * connection the whole time; with a pool of ten connections a few parallel logins would starve
 * every other request. Each database call here runs in its own short transaction: the account is
 * read by the repository, and the new tokens are stored by {@link RefreshTokenService}.
 *
 * <p>Neither the login, nor the password, nor a token is ever logged: only ids.
 */
@Service
public class AuthService {

  private static final Logger LOGGER = LogManager.getLogger(AuthService.class);

  /** Any text. Its hash is what the password is compared with when the login is unknown. */
  private static final String DUMMY_PASSWORD = "a password that no account has";

  private final CredentialRepository credentialRepository;
  private final PasswordEncoder passwordEncoder;
  private final RefreshTokenService refreshTokenService;

  /**
   * A hash made by the same encoder as the real ones, so comparing with it costs the same.
   * It is computed once, when the service is created.
   */
  private final String dummyHash;

  public AuthService(CredentialRepository credentialRepository, PasswordEncoder passwordEncoder,
      RefreshTokenService refreshTokenService) {
    this.credentialRepository = credentialRepository;
    this.passwordEncoder = passwordEncoder;
    this.refreshTokenService = refreshTokenService;
    this.dummyHash = passwordEncoder.encode(DUMMY_PASSWORD);
  }

  /**
   * Checks a login and a password and issues a pair of tokens.
   *
   * <p>An unknown login and a wrong password end in the same exception, and the work that is done
   * is the same: one BCrypt comparison in both cases, against the real hash or against a dummy
   * one, whose result is ignored. So neither the answer nor its time shows whether the login
   * exists.
   *
   * <p>A password of more than 72 bytes is refused without being compared. BCrypt reads only
   * the first 72 bytes, so it would accept the real password followed by anything. Only the
   * length of the caller's own input decides how long this takes, so nothing is revealed.
   *
   * @param login the login as the user typed it; stripped and lowercased like at registration
   * @param password the raw password
   * @return the new access token and refresh token
   * @throws InvalidCredentialsException if the login is unknown or the password is wrong
   */
  public TokenPair login(String login, String password) {
    Optional<Credential> account =
        credentialRepository.findByLogin(CredentialService.normalize(login));
    String hash = account.map(Credential::getPasswordHash).orElse(dummyHash);
    boolean passwordMatches =
        PasswordPolicy.isWithinBcryptLimit(password) && passwordEncoder.matches(password, hash);
    if (account.isEmpty() || !passwordMatches) {
      if (account.isEmpty()) {
        LOGGER.info("Login failed: unknown login");
      } else {
        LOGGER.info("Login failed for credential {}", account.get().getId());
      }
      throw new InvalidCredentialsException();
    }
    TokenPair pair = refreshTokenService.issuePair(account.get());
    LOGGER.info("Credential {} logged in", account.get().getId());
    return pair;
  }
}
