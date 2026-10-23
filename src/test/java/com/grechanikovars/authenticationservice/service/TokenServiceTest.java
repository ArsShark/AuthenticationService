package com.grechanikovars.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.grechanikovars.authenticationservice.TestEntities;
import com.grechanikovars.authenticationservice.TestKeys;
import com.grechanikovars.authenticationservice.config.JwtConfig;
import com.grechanikovars.authenticationservice.config.JwtProperties;
import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.integration.MutableClock;
import com.grechanikovars.authenticationservice.security.JwtKeys;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

/**
 * Checks what the tokens contain, how they are read back and what is refused, with the real
 * encoder and decoder of the application and a clock that the test moves.
 *
 * <p>The clock stands months in the past on purpose: tokens are still accepted, so the time of
 * every check comes from the application clock.
 */
class TokenServiceTest {

  private static final Instant NOW = Instant.parse("2026-01-15T10:00:00Z");
  private static final String ISSUER = "authentication-service";
  private static final Duration ACCESS_TTL = Duration.ofMinutes(15);
  private static final Duration REFRESH_TTL = Duration.ofDays(7);
  private static final String HASH = "x".repeat(60);

  private static final Set<String> ACCESS_CLAIMS =
      Set.of("iss", "sub", "iat", "exp", "jti", "token_type", "role", "email", "userId");
  private static final Set<String> REFRESH_CLAIMS =
      Set.of("iss", "sub", "iat", "exp", "jti", "token_type");

  private final MutableClock clock = new MutableClock(NOW);
  private final JwtKeys keys = TestKeys.jwtKeys();
  private final JwtProperties properties =
      new JwtProperties(TestKeys.PRIVATE_KEY_BASE64, ACCESS_TTL, REFRESH_TTL, ISSUER);
  private final JwtConfig config = new JwtConfig();
  private final JwtEncoder encoder = config.jwtEncoder(keys);
  private final JwtDecoder decoder = config.jwtDecoder(keys, properties, clock);
  private final TokenService tokens = new TokenService(encoder, decoder, properties, clock);

  private final Credential user = TestEntities.withDatabaseValues(
      new Credential("user@example.com", HASH, Role.USER, 3L), 7L, NOW);
  private final Credential admin = TestEntities.withDatabaseValues(
      new Credential("admin@example.com", HASH, Role.ADMIN, null), 1L, NOW);

  // ---------------------------------------------------------------- issuing

  @Test
  void accessTokenCarriesExactlyTheAgreedClaims() {
    IssuedToken issued = tokens.issueAccessToken(user);
    Jwt jwt = decoder.decode(issued.value());

    assertAll(
        () -> assertEquals(ACCESS_CLAIMS, jwt.getClaims().keySet()),
        () -> assertEquals(ISSUER, jwt.getClaimAsString("iss")),
        () -> assertEquals("7", jwt.getSubject()),
        () -> assertEquals(3L, ((Number) jwt.getClaims().get("userId")).longValue()),
        () -> assertEquals("USER", jwt.getClaimAsString("role")),
        () -> assertEquals("user@example.com", jwt.getClaimAsString("email")),
        () -> assertEquals("access", jwt.getClaimAsString("token_type")),
        () -> assertEquals(issued.jti().toString(), jwt.getId()),
        () -> assertEquals(NOW, jwt.getIssuedAt()),
        () -> assertEquals(NOW.plus(ACCESS_TTL), jwt.getExpiresAt()));
  }

  @Test
  void accessTokenOfAnAdminWithoutProfileHasNoUserIdClaim() {
    Jwt jwt = decoder.decode(tokens.issueAccessToken(admin).value());

    assertAll(
        () -> assertFalse(jwt.getClaims().containsKey("userId")),
        () -> assertEquals("ADMIN", jwt.getClaimAsString("role")),
        () -> assertEquals("1", jwt.getSubject()));
  }

  /** A JWT has whole seconds only, and the stored expiry must equal the claim. */
  @Test
  void timesAreCutToWholeSecondsAndMatchTheToken() {
    clock.set(NOW.plusMillis(789));

    IssuedToken issued = tokens.issueRefreshToken(user);
    Jwt jwt = decoder.decode(issued.value());

    assertAll(
        () -> assertEquals(NOW, issued.issuedAt()),
        () -> assertEquals(NOW.plus(REFRESH_TTL), issued.expiresAt()),
        () -> assertEquals(issued.issuedAt(), jwt.getIssuedAt()),
        () -> assertEquals(issued.expiresAt(), jwt.getExpiresAt()));
  }

  @Test
  void everyTokenGetsItsOwnJti() {
    IssuedToken first = tokens.issueRefreshToken(user);
    IssuedToken second = tokens.issueRefreshToken(user);

    assertNotEquals(first.jti(), second.jti());
  }

  /** The role and the profile are read from the database when a refresh token is used. */
  @Test
  void refreshTokenCarriesNothingButTheAgreedClaims() {
    IssuedToken issued = tokens.issueRefreshToken(user);
    Jwt jwt = decoder.decode(issued.value());

    assertAll(
        () -> assertEquals(REFRESH_CLAIMS, jwt.getClaims().keySet()),
        () -> assertEquals("refresh", jwt.getClaimAsString("token_type")),
        () -> assertEquals("7", jwt.getSubject()),
        () -> assertEquals(issued.jti().toString(), jwt.getId()),
        () -> assertEquals(NOW.plus(REFRESH_TTL), jwt.getExpiresAt()));
  }

  @Test
  void cannotIssueATokenForAnAccountThatWasNotSaved() {
    Credential unsaved = new Credential("new@example.com", HASH, Role.USER, 5L);

    assertAll(
        () -> assertThrows(IllegalArgumentException.class,
            () -> tokens.issueAccessToken(unsaved)),
        () -> assertThrows(IllegalArgumentException.class,
            () -> tokens.issueRefreshToken(unsaved)));
  }

  // ---------------------------------------------------------------- reading

  @Test
  void readsAnAccessToken() {
    IssuedToken issued = tokens.issueAccessToken(user);

    assertEquals(
        Optional.of(new AccessTokenClaims(7L, 3L, Role.USER, "user@example.com",
            issued.expiresAt())),
        tokens.parseAccessToken(issued.value()));
  }

  @Test
  void readsAnAccessTokenOfAnAdminWithoutProfile() {
    IssuedToken issued = tokens.issueAccessToken(admin);

    assertEquals(
        Optional.of(new AccessTokenClaims(1L, null, Role.ADMIN, "admin@example.com",
            issued.expiresAt())),
        tokens.parseAccessToken(issued.value()));
  }

  @Test
  void readsARefreshToken() {
    IssuedToken issued = tokens.issueRefreshToken(user);

    assertEquals(
        Optional.of(new RefreshTokenClaims(7L, issued.jti(), issued.expiresAt())),
        tokens.parseRefreshToken(issued.value()));
  }

  /** Both are signed with the same key, so only the claim {@code token_type} tells them apart. */
  @Test
  void anAccessTokenIsNotARefreshTokenAndTheOtherWayRound() {
    String access = tokens.issueAccessToken(user).value();
    String refresh = tokens.issueRefreshToken(user).value();

    assertAll(
        () -> assertTrue(tokens.parseAccessToken(refresh).isEmpty()),
        () -> assertTrue(tokens.parseRefreshToken(access).isEmpty()));
  }

  @Test
  void anAccessTokenExpiresWithoutAnyClockSkew() {
    IssuedToken issued = tokens.issueAccessToken(user);

    clock.set(issued.expiresAt());
    assertTrue(tokens.parseAccessToken(issued.value()).isPresent(), "valid at the second of exp");

    clock.set(issued.expiresAt().plusSeconds(1));
    assertTrue(tokens.parseAccessToken(issued.value()).isEmpty(), "expired one second later");
  }

  @Test
  void aRefreshTokenExpiresWithoutAnyClockSkew() {
    IssuedToken issued = tokens.issueRefreshToken(user);

    clock.set(issued.expiresAt());
    assertTrue(tokens.parseRefreshToken(issued.value()).isPresent(), "valid at the second of exp");

    clock.set(issued.expiresAt().plusSeconds(1));
    assertTrue(tokens.parseRefreshToken(issued.value()).isEmpty(), "expired one second later");
  }

  @Test
  void refusesTokensSignedWithAnotherKey() {
    TokenService foreign = serviceWith(
        JwtKeys.fromPkcs8Base64(TestKeys.toPkcs8Base64(TestKeys.generateRsa(2048).getPrivate())),
        properties);

    assertAll(
        () -> assertTrue(tokens.parseAccessToken(
            foreign.issueAccessToken(user).value()).isEmpty()),
        () -> assertTrue(tokens.parseRefreshToken(
            foreign.issueRefreshToken(user).value()).isEmpty()));
  }

  @Test
  void refusesTokensOfAnotherIssuer() {
    TokenService foreign = serviceWith(keys,
        new JwtProperties(TestKeys.PRIVATE_KEY_BASE64, ACCESS_TTL, REFRESH_TTL, "someone-else"));

    assertAll(
        () -> assertTrue(tokens.parseAccessToken(
            foreign.issueAccessToken(user).value()).isEmpty()),
        () -> assertTrue(tokens.parseRefreshToken(
            foreign.issueRefreshToken(user).value()).isEmpty()));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"  ", "abc", "a.b.c", "...", "eyJhbGciOiJSUzI1NiJ9.e30.", "Bearer abc"})
  void anAccessTokenParserNeverThrowsOnGarbage(String garbage) {
    assertTrue(tokens.parseAccessToken(garbage).isEmpty());
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"  ", "abc", "a.b.c", "...", "eyJhbGciOiJSUzI1NiJ9.e30.", "Bearer abc"})
  void aRefreshTokenParserNeverThrowsOnGarbage(String garbage) {
    assertTrue(tokens.parseRefreshToken(garbage).isEmpty());
  }

  @Test
  void refusesAHugeString() {
    String huge = "a".repeat(200_000);

    assertAll(
        () -> assertTrue(tokens.parseAccessToken(huge).isEmpty()),
        () -> assertTrue(tokens.parseRefreshToken(huge).isEmpty()));
  }

  /**
   * One character in the middle of the signature is changed. The last character is not used for
   * this: a 2048-bit signature leaves unused bits in it, so changing it may change nothing.
   */
  @Test
  void refusesATokenWithAChangedSignature() {
    String access = tokens.issueAccessToken(user).value();
    String refresh = tokens.issueRefreshToken(user).value();

    assertAll(
        () -> assertTrue(tokens.parseAccessToken(changeInSignature(access)).isEmpty()),
        () -> assertTrue(tokens.parseRefreshToken(changeInSignature(refresh)).isEmpty()));
  }

  /**
   * The token is signed by this service's own key, so it passes the signature check, and still
   * must be refused because its claims do not have the shape the service issues.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("malformedAccessTokens")
  void refusesAnAccessTokenWithMalformedClaims(String name, Consumer<JwtClaimsSet.Builder> change) {
    String token = signedAccess(change);

    assertTrue(tokens.parseAccessToken(token).isEmpty(), name);
  }

  static Stream<Arguments> malformedAccessTokens() {
    return Stream.of(
        malformed("the role is not a known role", b -> b.claim("role", "SUPERUSER")),
        malformed("the role is missing", b -> b.claims(m -> m.remove("role"))),
        malformed("the role is a number", b -> b.claim("role", 1)),
        malformed("the subject is not a number", b -> b.subject("abc")),
        malformed("the subject is zero", b -> b.subject("0")),
        malformed("the subject is negative", b -> b.subject("-5")),
        malformed("the email is missing", b -> b.claims(m -> m.remove("email"))),
        malformed("the email is blank", b -> b.claim("email", "  ")),
        malformed("the userId is text", b -> b.claim("userId", "3")),
        malformed("the userId is a fraction", b -> b.claim("userId", 3.5)),
        malformed("a user has no userId", b -> b.claims(m -> m.remove("userId"))),
        malformed("the token type is missing", b -> b.claims(m -> m.remove("token_type"))),
        malformed("the token type has another case", b -> b.claim("token_type", "ACCESS")));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("malformedRefreshTokens")
  void refusesARefreshTokenWithMalformedClaims(String name,
      Consumer<JwtClaimsSet.Builder> change) {
    String token = signedRefresh(change);

    assertTrue(tokens.parseRefreshToken(token).isEmpty(), name);
  }

  static Stream<Arguments> malformedRefreshTokens() {
    return Stream.of(
        malformed("the subject is not a number", b -> b.subject("abc")),
        malformed("the jti is missing", b -> b.claims(m -> m.remove("jti"))),
        malformed("the jti is not a UUID", b -> b.id("not-a-uuid")),
        malformed("the jti is a lenient UUID", b -> b.id("1-1-1-1-1")),
        malformed("the token type is access", b -> b.claim("token_type", "access")));
  }

  // ---------------------------------------------------------------- secrets in toString

  @Test
  void toStringOfTheValuesDoesNotPrintTheTokenOrTheEmail() {
    IssuedToken issued = tokens.issueAccessToken(user);
    AccessTokenClaims claims = tokens.parseAccessToken(issued.value()).orElseThrow();

    assertAll(
        () -> assertFalse(issued.toString().contains(issued.value().substring(0, 20))),
        () -> assertTrue(issued.toString().contains(issued.jti().toString())),
        () -> assertFalse(claims.toString().contains("user@example.com")),
        () -> assertTrue(claims.toString().contains("credentialId=7")));
  }

  // ---------------------------------------------------------------- helpers

  private TokenService serviceWith(JwtKeys otherKeys, JwtProperties otherProperties) {
    return new TokenService(config.jwtEncoder(otherKeys),
        config.jwtDecoder(otherKeys, otherProperties, clock), otherProperties, clock);
  }

  /** Signs an access token that is valid, then lets the test change it. */
  private String signedAccess(Consumer<JwtClaimsSet.Builder> change) {
    JwtClaimsSet.Builder builder = JwtClaimsSet.builder()
        .issuer(ISSUER)
        .subject("7")
        .id(UUID.randomUUID().toString())
        .issuedAt(NOW)
        .expiresAt(NOW.plus(ACCESS_TTL))
        .claim("token_type", "access")
        .claim("role", "USER")
        .claim("email", "user@example.com")
        .claim("userId", 3L);
    return sign(builder, change);
  }

  /** Signs a refresh token that is valid, then lets the test change it. */
  private String signedRefresh(Consumer<JwtClaimsSet.Builder> change) {
    JwtClaimsSet.Builder builder = JwtClaimsSet.builder()
        .issuer(ISSUER)
        .subject("7")
        .id(UUID.randomUUID().toString())
        .issuedAt(NOW)
        .expiresAt(NOW.plus(REFRESH_TTL))
        .claim("token_type", "refresh");
    return sign(builder, change);
  }

  private String sign(JwtClaimsSet.Builder builder, Consumer<JwtClaimsSet.Builder> change) {
    change.accept(builder);
    return encoder.encode(JwtEncoderParameters.from(builder.build())).getTokenValue();
  }

  private static Arguments malformed(String name, Consumer<JwtClaimsSet.Builder> change) {
    return Arguments.of(name, change);
  }

  private static String changeInSignature(String token) {
    int position = token.lastIndexOf('.') + 1 + 10;
    char changed = token.charAt(position) == 'A' ? 'B' : 'A';
    return String.format("%s%c%s",
        token.substring(0, position), changed, token.substring(position + 1));
  }
}
