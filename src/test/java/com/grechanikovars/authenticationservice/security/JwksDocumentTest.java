package com.grechanikovars.authenticationservice.security;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.grechanikovars.authenticationservice.TestKeys;
import com.grechanikovars.authenticationservice.config.JwtConfig;
import com.grechanikovars.authenticationservice.config.JwtProperties;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Checks the published key set: what it says, that it holds the public key and nothing private,
 * and that a token of the service can be verified with the published key alone, which is what
 * the other services do.
 */
class JwksDocumentTest {

  private static final Instant NOW = Instant.parse("2026-10-19T10:00:00Z");

  private final JwtKeys keys = TestKeys.jwtKeys();
  private final JwksDocument document = JwksDocument.from(keys);

  @Test
  void publishesOneKeyWithExactlyTheAgreedMembers() {
    Map<String, Object> key = onlyKey();

    assertAll(
        () -> assertEquals(Set.of("keys"), document.jwkSet().keySet()),
        () -> assertEquals(Set.of("kty", "use", "alg", "kid", "n", "e"), key.keySet(),
            "no private member such as d, p, q, dp, dq or qi"),
        () -> assertEquals("RSA", key.get("kty")),
        () -> assertEquals("sig", key.get("use")),
        () -> assertEquals("RS256", key.get("alg")),
        () -> assertEquals(keys.keyId(), key.get("kid")));
  }

  @Test
  void theKeyMaterialIsThePublicKeyOfThePair() {
    Map<String, Object> key = onlyKey();
    RSAPublicKey expected = keys.publicKey();

    assertAll(
        () -> assertEquals(expected.getModulus(), decodeNumber(key.get("n"))),
        () -> assertEquals(expected.getPublicExponent(), decodeNumber(key.get("e"))));
  }

  /** What a client does: rebuild the key from n and e, and verify a token with nothing else. */
  @Test
  void aTokenOfTheServiceIsVerifiedWithThePublishedKeyAlone() throws Exception {
    JwtProperties properties = new JwtProperties(TestKeys.PRIVATE_KEY_BASE64,
        Duration.ofMinutes(15), Duration.ofDays(7), "authentication-service");
    String token = new JwtConfig().jwtEncoder(keys)
        .encode(JwtEncoderParameters.from(JwtClaimsSet.builder()
            .issuer(properties.issuer())
            .subject("42")
            .issuedAt(NOW)
            .expiresAt(NOW.plus(properties.accessTtl()))
            .build()))
        .getTokenValue();
    Map<String, Object> key = onlyKey();
    RSAPublicKey published = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
        new RSAPublicKeySpec(decodeNumber(key.get("n")), decodeNumber(key.get("e"))));
    NimbusJwtDecoder clientDecoder = NimbusJwtDecoder.withPublicKey(published).build();
    // Only the signature is the point here; the clock of the test is far from the real one.
    clientDecoder.setJwtValidator(jwt -> OAuth2TokenValidatorResult.success());

    Jwt decoded = clientDecoder.decode(token);

    assertAll(
        () -> assertEquals("42", decoded.getSubject()),
        () -> assertEquals(key.get("kid"), decoded.getHeaders().get("kid")));
  }

  @Test
  void theDocumentCannotBeChanged() {
    assertThrows(UnsupportedOperationException.class,
        () -> document.jwkSet().put("another", "member"));
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> onlyKey() {
    List<Object> list = (List<Object>) document.jwkSet().get("keys");
    assertEquals(1, list.size());
    return (Map<String, Object>) list.get(0);
  }

  private static BigInteger decodeNumber(Object base64Url) {
    return new BigInteger(1, Base64.getUrlDecoder().decode((String) base64Url));
  }
}
