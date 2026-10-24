package com.grechanikovars.authenticationservice.service;

import com.grechanikovars.authenticationservice.config.JwtProperties;
import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

/**
 * Signs access and refresh tokens and reads them back.
 *
 * <p>The service works only with the tokens themselves: it never touches the database, so it has
 * no transaction. Storing and revoking refresh tokens is the job of the refresh token service.
 * It does not log either: a token is a credential, and the callers log what happened with ids
 * only.
 *
 * <p>The claims of an access token are {@code sub} (the id of the account), {@code userId} (the
 * id of the profile in User Service; absent for an admin that has none), {@code role},
 * {@code email} (the login), {@code jti}, {@code iss}, {@code iat}, {@code exp} and
 * {@code token_type}. A refresh token has only {@code sub}, {@code jti}, {@code iss},
 * {@code iat}, {@code exp} and {@code token_type}.
 *
 * <p>Both times come from the application {@link Clock} and are cut to whole seconds, because a
 * JWT has no finer resolution and the stored {@code expires_at} of a refresh token must equal its
 * {@code exp}.
 */
@Service
public class TokenService {

  static final String CLAIM_TOKEN_TYPE = "token_type";
  static final String CLAIM_ROLE = "role";
  static final String CLAIM_EMAIL = "email";
  static final String CLAIM_USER_ID = "userId";

  private final JwtEncoder encoder;
  private final JwtDecoder decoder;
  private final JwtProperties properties;
  private final Clock clock;

  public TokenService(JwtEncoder encoder, JwtDecoder decoder, JwtProperties properties,
      Clock clock) {
    this.encoder = encoder;
    this.decoder = decoder;
    this.properties = properties;
    this.clock = clock;
  }

  /**
   * Signs an access token for an account.
   *
   * @param credential the account; it must have been saved, because its id is the subject
   * @return the token, valid for {@code app.jwt.access-ttl}
   */
  public IssuedToken issueAccessToken(Credential credential) {
    Instant issuedAt = now();
    Instant expiresAt = issuedAt.plus(properties.accessTtl()).truncatedTo(ChronoUnit.SECONDS);
    UUID jti = UUID.randomUUID();
    JwtClaimsSet.Builder claims =
        baseClaims(credential, jti, issuedAt, expiresAt, TokenType.ACCESS)
            .claim(CLAIM_ROLE, credential.getRole().name())
            .claim(CLAIM_EMAIL, credential.getLogin());
    if (credential.getUserId() != null) {
      claims.claim(CLAIM_USER_ID, credential.getUserId());
    }
    return sign(claims.build(), jti, issuedAt, expiresAt);
  }

  /**
   * Signs a refresh token for an account. The caller stores the returned {@code jti}, because
   * that row is what makes the token valid and what a rotation revokes.
   *
   * @param credential the account; it must have been saved, because its id is the subject
   * @return the token, valid for {@code app.jwt.refresh-ttl}
   */
  public IssuedToken issueRefreshToken(Credential credential) {
    Instant issuedAt = now();
    Instant expiresAt = issuedAt.plus(properties.refreshTtl()).truncatedTo(ChronoUnit.SECONDS);
    UUID jti = UUID.randomUUID();
    JwtClaimsSet claims =
        baseClaims(credential, jti, issuedAt, expiresAt, TokenType.REFRESH).build();
    return sign(claims, jti, issuedAt, expiresAt);
  }

  /**
   * Reads an access token.
   *
   * <p>The token is accepted only if the signature, the issuer and the time are right and it
   * really is an access token. Every other case gives an empty result, never an exception, and
   * the caller cannot tell the cases apart on purpose.
   *
   * @param token the compact serialized token, may be {@code null} or garbage
   * @return the claims, or empty if the token is not a valid access token
   */
  public Optional<AccessTokenClaims> parseAccessToken(String token) {
    return decode(token, TokenType.ACCESS).flatMap(TokenService::toAccessClaims);
  }

  /**
   * Reads a refresh token. The rules are those of {@link #parseAccessToken(String)}, for the
   * other type.
   *
   * <p>Whether the token is still known to the database is not checked here.
   *
   * @param token the compact serialized token, may be {@code null} or garbage
   * @return the claims, or empty if the token is not a valid refresh token
   */
  public Optional<RefreshTokenClaims> parseRefreshToken(String token) {
    return decode(token, TokenType.REFRESH).flatMap(TokenService::toRefreshClaims);
  }

  private Instant now() {
    return Instant.now(clock).truncatedTo(ChronoUnit.SECONDS);
  }

  private JwtClaimsSet.Builder baseClaims(Credential credential, UUID jti,
      Instant issuedAt, Instant expiresAt, TokenType type) {
    if (credential.getId() == null) {
      throw new IllegalArgumentException("The account must be saved before a token is issued");
    }
    return JwtClaimsSet.builder()
        .issuer(properties.issuer())
        .subject(String.valueOf(credential.getId()))
        .id(jti.toString())
        .issuedAt(issuedAt)
        .expiresAt(expiresAt)
        .claim(CLAIM_TOKEN_TYPE, type.claimValue());
  }

  private IssuedToken sign(JwtClaimsSet claims, UUID jti, Instant issuedAt, Instant expiresAt) {
    String value = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    return new IssuedToken(value, jti, issuedAt, expiresAt);
  }

  /**
   * Verifies the token with the decoder and checks its type. The decoder checks the signature,
   * the issuer and the time.
   */
  private Optional<Jwt> decode(String token, TokenType expected) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    try {
      Jwt jwt = decoder.decode(token);
      boolean rightType = expected.claimValue().equals(jwt.getClaims().get(CLAIM_TOKEN_TYPE));
      return rightType ? Optional.of(jwt) : Optional.empty();
    } catch (JwtException | IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  /**
   * Reads the claims of an access token that has a valid signature. A token that this service
   * signed always has the right shape; the checks protect against a token of another version or
   * a bug, and turn any such token into an empty result.
   */
  private static Optional<AccessTokenClaims> toAccessClaims(Jwt jwt) {
    Map<String, Object> claims = jwt.getClaims();
    Long credentialId = toId(claims.get("sub"));
    Role role = toRole(claims.get(CLAIM_ROLE));
    String login = claims.get(CLAIM_EMAIL) instanceof String text ? text : null;
    Object rawUserId = claims.get(CLAIM_USER_ID);
    Long userId = toLong(rawUserId);
    boolean userIdIsBroken = rawUserId != null && userId == null;
    boolean userWithoutProfile = role == Role.USER && userId == null;
    if (credentialId == null || role == null || userIdIsBroken || userWithoutProfile
        || login == null || login.isBlank() || jwt.getExpiresAt() == null) {
      return Optional.empty();
    }
    return Optional.of(
        new AccessTokenClaims(credentialId, userId, role, login, jwt.getExpiresAt()));
  }

  private static Optional<RefreshTokenClaims> toRefreshClaims(Jwt jwt) {
    Map<String, Object> claims = jwt.getClaims();
    Long credentialId = toId(claims.get("sub"));
    UUID jti = toUuid(claims.get("jti"));
    if (credentialId == null || jti == null || jwt.getExpiresAt() == null) {
      return Optional.empty();
    }
    return Optional.of(new RefreshTokenClaims(credentialId, jti, jwt.getExpiresAt()));
  }

  /** Reads the id of an account: a positive number written as text. */
  private static Long toId(Object value) {
    if (!(value instanceof String text)) {
      return null;
    }
    try {
      long id = Long.parseLong(text);
      return id > 0 ? id : null;
    } catch (NumberFormatException e) {
      return null;
    }
  }

  /** Reads a number claim that is a whole number; anything else is {@code null}. */
  private static Long toLong(Object value) {
    boolean whole = value instanceof Long || value instanceof Integer;
    return whole ? ((Number) value).longValue() : null;
  }

  private static Role toRole(Object value) {
    if (!(value instanceof String text)) {
      return null;
    }
    try {
      return Role.valueOf(text);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /** Reads a UUID in its canonical form; the lenient forms of {@code UUID.fromString} are not. */
  private static UUID toUuid(Object value) {
    if (!(value instanceof String text)) {
      return null;
    }
    try {
      UUID uuid = UUID.fromString(text);
      return uuid.toString().equals(text) ? uuid : null;
    } catch (IllegalArgumentException e) {
      return null;
    }
  }
}
