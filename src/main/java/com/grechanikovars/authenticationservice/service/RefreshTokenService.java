package com.grechanikovars.authenticationservice.service;

import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.RefreshToken;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import com.grechanikovars.authenticationservice.repository.RefreshTokenRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Issues pairs of tokens and keeps the table of refresh tokens: it stores a new token and
 * rotates a used one.
 *
 * <p>A refresh token is valid while its row exists and {@code revoked_at} is empty. A token is
 * used only once: a rotation revokes the old row and stores a new pair. If a token that is no
 * longer valid comes again, somebody may have copied it, so every valid token of that account is
 * revoked.
 *
 * <p>The service logs ids of accounts only, never a token, a {@code jti} or a login.
 *
 * <p>Every method that writes has its own {@link Transactional} and the {@code AuthService}
 * that calls them has none. It checks the password with BCrypt, which takes tens of
 * milliseconds, and a transaction around that would hold a database connection all the time.
 */
@Service
@Transactional(readOnly = true)
public class RefreshTokenService {

  private static final Logger LOGGER = LogManager.getLogger(RefreshTokenService.class);

  private final RefreshTokenRepository refreshTokenRepository;
  private final CredentialRepository credentialRepository;
  private final TokenService tokenService;
  private final Clock clock;

  public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
      CredentialRepository credentialRepository, TokenService tokenService, Clock clock) {
    this.refreshTokenRepository = refreshTokenRepository;
    this.credentialRepository = credentialRepository;
    this.tokenService = tokenService;
    this.clock = clock;
  }

  /**
   * Signs a new pair of tokens for an account and stores the row of the refresh token.
   *
   * <p>This is what a login does. The account may be a detached entity: only its id is used to
   * link the row.
   *
   * @param credential an account that has been saved
   * @return the access token and the refresh token
   */
  @Transactional
  public TokenPair issuePair(Credential credential) {
    return createPair(credential);
  }

  /**
   * Exchanges a refresh token for a new pair of tokens.
   *
   * <p>The first step is one SQL statement that revokes the token only if it is still valid.
   * Everything depends on how many rows it changed:
   *
   * <ul>
   *   <li>one row: this call owns the token. The account is read again from the database, so the
   *       role and the profile in the new access token are current, and a new pair is issued;
   *   <li>no row: the token was used before, was revoked, or is unknown. Every valid token of the
   *       account is revoked and nothing is issued.
   * </ul>
   *
   * <p>The refusal is an empty result and not an exception on purpose. An exception that leaves
   * a {@code @Transactional} method rolls the transaction back, and that would undo the
   * revocation of the other tokens. The caller turns the empty result into a 401 after this
   * transaction has committed.
   *
   * <p>If several requests use the same token at the same time, one of them wins and gets a
   * pair. The others wait for its row lock and then find no valid row, so they revoke every
   * valid token of the account, including the new one of the winner. This is the strict rule on
   * purpose: there is no grace period, and a double click can end a session.
   *
   * @param claims the claims of a refresh token whose signature, issuer and expiry are checked
   * @return the new pair, or empty if the token cannot be used
   */
  @Transactional
  public Optional<TokenPair> rotate(RefreshTokenClaims claims) {
    Instant now = Instant.now(clock);
    int claimed = refreshTokenRepository.revokeByJti(claims.jti(), now);
    if (claimed == 0) {
      int revoked = refreshTokenRepository.revokeAllByCredentialId(claims.credentialId(), now);
      LOGGER.warn("Refresh token of credential {} is not valid; {} valid tokens revoked",
          claims.credentialId(), revoked);
      return Optional.empty();
    }
    Optional<Credential> credential = credentialRepository.findById(claims.credentialId());
    if (credential.isEmpty()) {
      LOGGER.warn("A refresh token of credential {} was used, but the account does not exist",
          claims.credentialId());
      return Optional.empty();
    }
    return Optional.of(createPair(credential.get()));
  }

  /**
   * Signs both tokens and stores the row of the refresh token. The row holds the {@code jti}
   * and the expiry, which equals the {@code exp} claim, and never the token itself.
   */
  private TokenPair createPair(Credential credential) {
    IssuedToken access = tokenService.issueAccessToken(credential);
    IssuedToken refresh = tokenService.issueRefreshToken(credential);
    refreshTokenRepository.save(
        new RefreshToken(refresh.jti(), credential, refresh.expiresAt()));
    return new TokenPair(access, refresh);
  }
}
