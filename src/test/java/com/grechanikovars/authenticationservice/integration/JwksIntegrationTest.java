package com.grechanikovars.authenticationservice.integration;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.TestKeys;
import com.grechanikovars.authenticationservice.service.CredentialService;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Tests {@code GET /.well-known/jwks.json} through the whole stack, next to the login that signs
 * the tokens: the published key must be the one that verifies them.
 */
class JwksIntegrationTest extends AbstractIntegrationTest {

  private static final String JWKS_PATH = "/.well-known/jwks.json";
  private static final String LOGIN = "alice@example.com";
  private static final String PASSWORD = "s3cret-passw0rd";

  @Autowired
  private CredentialService credentialService;

  /**
   * The whole point of the endpoint. A client reads the key set, finds the key by the {@code kid}
   * in the header of a token, rebuilds the public key from it and verifies the signature.
   */
  @Test
  void thePublishedKeyVerifiesTheTokensThatTheLoginIssues() throws Exception {
    credentialService.register(LOGIN, PASSWORD, 7L);
    String accessToken = accessTokenOfLogin();

    JWKSet keySet = JWKSet.parse(bodyOf(jwks()));
    String kidOfTheToken = JsonPath.read(decodePart(accessToken, 0), "$.kid");
    JWK published = keySet.getKeyByKeyId(kidOfTheToken);
    NimbusJwtDecoder clientDecoder =
        NimbusJwtDecoder.withPublicKey(published.toRSAKey().toRSAPublicKey()).build();
    // Only the signature is the point; the clock of the test is far from the real one.
    clientDecoder.setJwtValidator(jwt -> OAuth2TokenValidatorResult.success());

    Jwt decoded = clientDecoder.decode(accessToken);

    assertAll(
        () -> assertEquals(1, keySet.getKeys().size()),
        () -> assertEquals(TestKeys.jwtKeys().keyId(), kidOfTheToken),
        () -> assertEquals("USER", decoded.getClaimAsString("role")));
  }

  @Test
  void isPublicAndCacheableForFiveMinutes() throws Exception {
    MvcResult result = mockMvc.perform(get(JWKS_PATH)).andExpectAll(
        status().isOk(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
        header().string(HttpHeaders.CACHE_CONTROL,
            allOf(containsString("max-age=300"), containsString("public")))).andReturn();

    assertNull(result.getResponse().getHeader(HttpHeaders.SET_COOKIE));
  }

  /**
   * The answer holds the public members and nothing else: not a private member of the key and
   * not a single byte of the private exponent.
   */
  @Test
  void holdsNoPrivatePartOfTheKey() throws Exception {
    String body = bodyOf(jwks());
    RSAPrivateKey privateKey = (RSAPrivateKey) TestKeys.KEY_PAIR.getPrivate();
    String privateExponent = base64Url(privateKey.getPrivateExponent());

    List<Map<String, Object>> keys = JsonPath.read(body, "$.keys");
    assertAll(
        () -> assertEquals(1, keys.size()),
        () -> assertEquals(Set.of("kty", "use", "alg", "kid", "n", "e"), keys.get(0).keySet()),
        () -> assertFalse(body.contains(privateExponent)),
        () -> assertFalse(body.contains(TestKeys.PRIVATE_KEY_BASE64.substring(0, 40))));
  }

  @Test
  void answersTheSameEveryTimeAndSignsWithTheKeyThatItPublishes() throws Exception {
    RSAPublicKey expected = TestKeys.jwtKeys().publicKey();

    String first = bodyOf(jwks());
    String second = bodyOf(jwks());

    JWK key = JWKSet.parse(first).getKeys().get(0);
    assertAll(
        () -> assertEquals(first, second),
        () -> assertEquals(expected, key.toRSAKey().toRSAPublicKey()));
  }

  /** Only GET is opened by the security rules. */
  @Test
  void postIsUnauthorized() throws Exception {
    mockMvc.perform(post(JWKS_PATH)).andExpect(status().isUnauthorized());
  }

  private MvcResult jwks() throws Exception {
    return mockMvc.perform(get(JWKS_PATH)).andExpect(status().isOk()).andReturn();
  }

  private String accessTokenOfLogin() throws Exception {
    String body = String.format("{\"login\": \"%s\", \"password\": \"%s\"}", LOGIN, PASSWORD);
    MvcResult result = mockMvc.perform(post("/api/auth/login")
        .contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpect(status().isOk()).andReturn();
    return JsonPath.read(bodyOf(result), "$.accessToken");
  }

  /** Decodes one of the three parts of a compact JWT: 0 is the header, 1 the payload. */
  private static String decodePart(String token, int index) {
    return new String(Base64.getUrlDecoder().decode(token.split("\\.")[index]),
        StandardCharsets.UTF_8);
  }

  private static String base64Url(BigInteger number) {
    byte[] bytes = number.toByteArray();
    byte[] unsigned = bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    return Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned);
  }

  private static String bodyOf(MvcResult result) throws Exception {
    return result.getResponse().getContentAsString(StandardCharsets.UTF_8);
  }
}
