package com.grechanikovars.authenticationservice.service;

import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.exception.InvalidCredentialsException;
import com.grechanikovars.authenticationservice.exception.InvalidRefreshTokenException;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import com.grechanikovars.authenticationservice.validation.PasswordPolicy;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Logs users in, exchanges their refresh tokens for new pairs of tokens and checks access
 * tokens.
 *
 * <p>The class has no {@code @Transactional}, on purpose. A login checks the password with
 * BCrypt, which takes tens of milliseconds, and a transaction around that would hold a database
 * connection the whole time; with a pool of ten connections a few parallel logins would starve
 * every other request. Each database call here runs in its own short transaction: the account is
 * read by the repository, and the tokens are stored and rotated by {@link RefreshTokenService}.
 *
 * <p>For a refresh the missing transaction matters in another way: {@code rotate} commits its own
 * transaction, including the revocation of the whole account after a reuse, and only then does
 * this class turn the empty result into an exception. An exception thrown inside a transaction
 * would roll the revocation back.
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
  private final TokenService tokenService;

  /**
   * A hash made by the same encoder as the real ones, so comparing with it costs the same.
   * It is computed once, when the service is created.
   */
  private final String dummyHash;

  public AuthService(CredentialRepository credentialRepository, PasswordEncoder passwordEncoder,
      RefreshTokenService refreshTokenService, TokenService tokenService) {
    this.credentialRepository = credentialRepository;
    this.passwordEncoder = passwordEncoder;
    this.refreshTokenService = refreshTokenService;
    this.tokenService = tokenService;
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

  /**
   * Exchanges a refresh token for a new pair of tokens.
   *
   * <p>The token is checked first without the database: the signature, the issuer, the expiry
   * and the type, so garbage, an expired token and an access token are refused at once and
   * change nothing. Then {@link RefreshTokenService#rotate} decides in the database whether the
   * token can still be used.
   *
   * <p>Every refusal ends in the same exception, whatever the cause, so the answer does not
   * show which check failed.
   *
   * @param refreshToken the refresh token as the client sent it
   * @return the new access token and refresh token; the used refresh token is revoked
   * @throws InvalidRefreshTokenException if the token is not valid or cannot be used
   */
  public TokenPair refresh(String refreshToken) {
    Optional<RefreshTokenClaims> parsed = tokenService.parseRefreshToken(refreshToken);
    if (parsed.isEmpty()) {
      LOGGER.info("Refresh failed: not a valid refresh token");
      throw new InvalidRefreshTokenException();
    }
    RefreshTokenClaims claims = parsed.get();
    Optional<TokenPair> rotated = refreshTokenService.rotate(claims);
    if (rotated.isEmpty()) {
      LOGGER.info("Refresh refused for credential {}", claims.credentialId());
      throw new InvalidRefreshTokenException();
    }
    LOGGER.info("Credential {} refreshed its tokens", claims.credentialId());
    return rotated.get();
  }

  /**
   * Checks an access token.
   *
   * <p>The checks are those that every service makes when it verifies a token with the public
   * key: the signature, the issuer, the expiry and the type. The database is not consulted, so
   * the answer is the same as the one a service gives on its own. A deleted account or a changed
   * role is noticed only when the token expires, which is at most the lifetime of an access
   * token.
   *
   * @param token the access token as the client sent it, may be garbage
   * @return the claims of a valid access token, or empty if the token is not a valid access token
   *     for any reason (a refresh token is not one)
   */
  public Optional<AccessTokenClaims> validate(String token) {
    return tokenService.parseAccessToken(token);
  }
}
