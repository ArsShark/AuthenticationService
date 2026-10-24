package com.grechanikovars.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.grechanikovars.authenticationservice.TestKeys;
import com.grechanikovars.authenticationservice.integration.MutableClock;
import com.grechanikovars.authenticationservice.security.JwksDocument;
import com.grechanikovars.authenticationservice.security.JwtKeys;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

/**
 * Checks the encoder and the decoder as Spring creates them from the settings: that a token
 * survives the round trip, what the decoder rejects, and that a wrong key or lifetime stops the
 * startup without printing the key.
 *
 * <p>The clock of these tests stands months in the past on purpose. A token issued at that time
 * is still accepted, which shows that the time of the check comes from the application clock and
 * not from the system clock.
 */
class JwtConfigTest {

  private static final Instant NOW = Instant.parse("2026-01-15T10:00:00Z");
  private static final String ISSUER = "authentication-service";

  private final MutableClock clock = new MutableClock(NOW);

  private final ApplicationContextRunner baseRunner = new ApplicationContextRunner()
      .withUserConfiguration(JwtConfig.class)
      .withBean(Clock.class, () -> clock)
      .withPropertyValues(
          "app.jwt.access-ttl=PT15M",
          "app.jwt.refresh-ttl=P7D",
          String.format("app.jwt.issuer=%s", ISSUER));

  private final ApplicationContextRunner runner = baseRunner.withPropertyValues(
      String.format("app.jwt.private-key=%s", TestKeys.PRIVATE_KEY_BASE64));

  @Test
  void aTokenSurvivesTheRoundTripAndKeepsItsHeader() {
    runner.run(context -> {
      JwtKeys keys = context.getBean(JwtKeys.class);
      String token = encode(context.getBean(JwtEncoder.class), ISSUER, NOW.plusSeconds(900));

      Jwt decoded = context.getBean(JwtDecoder.class).decode(token);

      assertAll(
          () -> assertEquals("42", decoded.getSubject()),
          () -> assertEquals(ISSUER, decoded.getClaimAsString("iss")),
          () -> assertEquals(NOW.plusSeconds(900), decoded.getExpiresAt()),
          () -> assertEquals("RS256", String.valueOf(decoded.getHeaders().get("alg"))),
          () -> assertEquals("JWT", String.valueOf(decoded.getHeaders().get("typ"))),
          () -> assertEquals(keys.keyId(), decoded.getHeaders().get("kid")));
    });
  }

  @Test
  void createsTheDocumentThatPublishesThePublicKey() {
    runner.run(context -> {
      JwtKeys keys = context.getBean(JwtKeys.class);
      JwksDocument document = context.getBean(JwksDocument.class);

      assertEquals(JwksDocument.from(keys), document);
    });
  }

  /** There is no clock skew: the token is valid up to its {@code exp} and not a second longer. */
  @Test
  void rejectsAnExpiredTokenWithoutAnyClockSkew() {
    runner.run(context -> {
      Instant expiresAt = NOW.plusSeconds(900);
      String token = encode(context.getBean(JwtEncoder.class), ISSUER, expiresAt);
      JwtDecoder decoder = context.getBean(JwtDecoder.class);

      clock.set(expiresAt);
      assertDoesNotThrow(() -> decoder.decode(token), "valid at the very second of exp");

      clock.set(expiresAt.plusSeconds(1));
      assertThrows(JwtValidationException.class, () -> decoder.decode(token));
    });
  }

  @Test
  void rejectsATokenOfAnotherIssuer() {
    runner.run(context -> {
      String token = encode(context.getBean(JwtEncoder.class), "someone-else",
          NOW.plusSeconds(900));

      assertThrows(JwtValidationException.class,
          () -> context.getBean(JwtDecoder.class).decode(token));
    });
  }

  @Test
  void rejectsATokenWithoutAnExpiry() {
    runner.run(context -> {
      JwtClaimsSet claims = JwtClaimsSet.builder()
          .issuer(ISSUER)
          .subject("42")
          .issuedAt(NOW)
          .build();
      String token = context.getBean(JwtEncoder.class)
          .encode(JwtEncoderParameters.from(claims)).getTokenValue();

      assertThrows(JwtValidationException.class,
          () -> context.getBean(JwtDecoder.class).decode(token));
    });
  }

  @Test
  void rejectsATokenSignedWithAnotherKey() {
    runner.run(context -> {
      JwtKeys other = JwtKeys.fromPkcs8Base64(
          TestKeys.toPkcs8Base64(TestKeys.generateRsa(2048).getPrivate()));
      String token = encode(new JwtConfig().jwtEncoder(other), ISSUER, NOW.plusSeconds(900));

      assertThrows(JwtException.class, () -> context.getBean(JwtDecoder.class).decode(token));
    });
  }

  /** A token with {@code alg=none} has no signature at all and must never be accepted. */
  @Test
  void rejectsAnUnsignedToken() {
    runner.run(context -> {
      String header = base64Url("{\"alg\":\"none\"}");
      String payload = base64Url(String.format("{\"iss\":\"%s\",\"sub\":\"42\",\"exp\":%d}",
          ISSUER, NOW.plusSeconds(900).getEpochSecond()));
      String unsigned = String.format("%s.%s.", header, payload);

      assertThrows(JwtException.class, () -> context.getBean(JwtDecoder.class).decode(unsigned));
    });
  }

  @Test
  void rejectsATokenWhosePayloadWasChanged() {
    runner.run(context -> {
      String token = encode(context.getBean(JwtEncoder.class), ISSUER, NOW.plusSeconds(900));
      String[] parts = token.split("\\.");
      String forgedPayload = base64Url(String.format("{\"iss\":\"%s\",\"sub\":\"1\",\"exp\":%d}",
          ISSUER, NOW.plusSeconds(900).getEpochSecond()));
      String forged = String.format("%s.%s.%s", parts[0], forgedPayload, parts[2]);

      assertThrows(JwtException.class, () -> context.getBean(JwtDecoder.class).decode(forged));
    });
  }

  @Test
  void startupFailsWithoutAKey() {
    baseRunner.withPropertyValues("app.jwt.private-key=").run(context -> {
      assertNotNull(context.getStartupFailure());
      assertTrue(allMessages(context.getStartupFailure()).contains("JWT_PRIVATE_KEY is not set"));
    });
  }

  /** The wrong format that {@code openssl genpkey -outform DER} writes; the key is not printed. */
  @Test
  void startupFailsForAKeyInTheWrongFormatAndDoesNotPrintIt() {
    byte[] pkcs8 = TestKeys.KEY_PAIR.getPrivate().getEncoded();
    String pkcs1 = Base64.getEncoder().encodeToString(Arrays.copyOfRange(pkcs8, 26, pkcs8.length));

    baseRunner.withPropertyValues(String.format("app.jwt.private-key=%s", pkcs1)).run(context -> {
      assertNotNull(context.getStartupFailure());
      String messages = allMessages(context.getStartupFailure());
      assertAll(
          () -> assertTrue(messages.contains("PKCS#8"), messages),
          () -> assertFalse(messages.contains(pkcs1.substring(0, 40)), messages));
    });
  }

  @Test
  void startupFailsWhenTheRefreshTokenDoesNotLiveLongerThanTheAccessToken() {
    runner.withPropertyValues("app.jwt.refresh-ttl=PT1M").run(context -> {
      assertNotNull(context.getStartupFailure());
      assertTrue(allMessages(context.getStartupFailure()).contains("app.jwt.refresh-ttl"));
    });
  }

  private static String encode(JwtEncoder encoder, String issuer, Instant expiresAt) {
    JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer(issuer)
        .subject("42")
        .issuedAt(NOW)
        .expiresAt(expiresAt)
        .build();
    return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
  }

  private static String base64Url(String text) {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(text.getBytes(StandardCharsets.UTF_8));
  }

  /** The messages of a failure and of all its causes in one string. */
  private static String allMessages(Throwable failure) {
    StringBuilder messages = new StringBuilder();
    for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
      messages.append(cause.getMessage()).append('\n');
    }
    return messages.toString();
  }
}
