package com.grechanikovars.authenticationservice.security;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.grechanikovars.authenticationservice.TestKeys;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Checks how the private key is read: what is accepted, what is rejected, and that no error
 * message repeats the value, because the value is a secret and the message reaches the log.
 */
class JwtKeysTest {

  private static final KeyPair PAIR = TestKeys.KEY_PAIR;
  private static final String KEY = TestKeys.PRIVATE_KEY_BASE64;

  /**
   * The size of the PKCS#8 wrapper around an RSA key of 2048 bits: the outer sequence (4 bytes),
   * the version (3), the algorithm identifier (15) and the header of the octet string (4). What
   * follows is the PKCS#1 key, the format that {@code openssl genpkey -outform DER} writes.
   */
  private static final int PKCS8_HEADER_LENGTH = 26;

  @Test
  void derivesThePublicKeyFromThePrivateKey() {
    JwtKeys keys = JwtKeys.fromPkcs8Base64(KEY);
    RSAPublicKey expected = (RSAPublicKey) PAIR.getPublic();

    assertAll(
        () -> assertEquals(expected.getModulus(), keys.publicKey().getModulus()),
        () -> assertEquals(expected.getPublicExponent(), keys.publicKey().getPublicExponent()),
        () -> assertEquals(PAIR.getPrivate(), keys.privateKey()));
  }

  /** The id is computed here again from the RFC 7638 rules, without the library of the code. */
  @Test
  void keyIdIsTheRfc7638ThumbprintOfThePublicKey() throws Exception {
    RSAPublicKey publicKey = (RSAPublicKey) PAIR.getPublic();
    String canonical = String.format("{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}",
        base64Url(unsigned(publicKey.getPublicExponent())),
        base64Url(unsigned(publicKey.getModulus())));
    byte[] digest = MessageDigest.getInstance("SHA-256")
        .digest(canonical.getBytes(StandardCharsets.UTF_8));

    assertEquals(base64Url(digest), JwtKeys.fromPkcs8Base64(KEY).keyId());
  }

  @Test
  void keyIdChangesWithTheKeyAndOnlyWithTheKey() {
    String another = TestKeys.toPkcs8Base64(TestKeys.generateRsa(2048).getPrivate());

    assertAll(
        () -> assertEquals(
            JwtKeys.fromPkcs8Base64(KEY).keyId(), JwtKeys.fromPkcs8Base64(KEY).keyId()),
        () -> assertNotEquals(
            JwtKeys.fromPkcs8Base64(KEY).keyId(), JwtKeys.fromPkcs8Base64(another).keyId()));
  }

  @Test
  void ignoresWhitespaceAroundTheValue() {
    String padded = String.format(" \n%s\r\n ", KEY);

    assertEquals(JwtKeys.fromPkcs8Base64(KEY).keyId(), JwtKeys.fromPkcs8Base64(padded).keyId());
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "\n\t "})
  void rejectsAMissingKey(String value) {
    IllegalStateException error =
        assertThrows(IllegalStateException.class, () -> JwtKeys.fromPkcs8Base64(value));

    assertEquals("JWT_PRIVATE_KEY is not set", error.getMessage());
  }

  /** {@code openssl base64} wraps lines at 64 characters unless it gets {@code -A}. */
  @Test
  void rejectsBase64ThatIsWrappedIntoSeveralLines() {
    String wrapped = KEY.replaceAll("(.{64})", "$1\n");

    assertRejected(wrapped, "one line");
  }

  @Test
  void rejectsAValueThatIsNotBase64() {
    assertRejected("super-secret-garbage-value", "not valid base64");
  }

  @Test
  void rejectsBytesThatAreNotAKey() {
    assertRejected(base64(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}), "PKCS#8");
  }

  /** The trap of {@code openssl genpkey -outform DER}: the key is valid, but not PKCS#8. */
  @Test
  void rejectsAnRsaKeyInPkcs1Format() {
    byte[] pkcs8 = PAIR.getPrivate().getEncoded();
    byte[] pkcs1 = Arrays.copyOfRange(pkcs8, PKCS8_HEADER_LENGTH, pkcs8.length);

    assertAll(
        () -> assertEquals(0x30, pkcs1[0] & 0xFF, "the inner key starts with a DER sequence"),
        () -> assertRejected(base64(pkcs1), "PKCS#8"));
  }

  @Test
  void rejectsAPublicKey() {
    assertRejected(base64(PAIR.getPublic().getEncoded()), "PKCS#8");
  }

  @Test
  void rejectsAKeyThatIsNotRsa() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);

    assertRejected(TestKeys.toPkcs8Base64(generator.generateKeyPair().getPrivate()), "PKCS#8");
  }

  @Test
  void rejectsAKeyShorterThan2048Bits() {
    String shortKey = TestKeys.toPkcs8Base64(TestKeys.generateRsa(1024).getPrivate());

    assertRejected(shortKey, "at least 2048 bits");
  }

  /** The public key is derived from the CRT parameters, so a key without them is useless. */
  @Test
  void rejectsAKeyWithoutCrtParameters() throws Exception {
    RSAPrivateCrtKey crt = (RSAPrivateCrtKey) PAIR.getPrivate();
    PrivateKey plain = KeyFactory.getInstance("RSA")
        .generatePrivate(new RSAPrivateKeySpec(crt.getModulus(), crt.getPrivateExponent()));

    assertRejected(TestKeys.toPkcs8Base64(plain), "CRT parameters");
  }

  @Test
  void toStringDoesNotPrintTheKey() {
    JwtKeys keys = JwtKeys.fromPkcs8Base64(KEY);
    String text = keys.toString();

    assertAll(
        () -> assertTrue(text.contains(keys.keyId())),
        () -> assertFalse(text.contains(KEY.substring(0, 40))),
        () -> assertFalse(text.contains(keys.privateKey().getPrivateExponent().toString())),
        () -> assertTrue(text.contains("privateKey=***")));
  }

  /**
   * Expects a rejection with the given part in the message, and checks that the message does not
   * contain the value that was rejected.
   */
  private static void assertRejected(String value, String messagePart) {
    IllegalStateException error =
        assertThrows(IllegalStateException.class, () -> JwtKeys.fromPkcs8Base64(value));

    assertAll(
        () -> assertTrue(error.getMessage().contains(messagePart), error.getMessage()),
        () -> assertTrue(error.getMessage().startsWith("JWT_PRIVATE_KEY"), error.getMessage()),
        () -> assertFalse(error.getMessage().contains(value.strip().substring(0, 8))),
        () -> assertNull(error.getCause()));
  }

  private static String base64(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  private static String base64Url(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /** The big-endian bytes of a positive number without the sign byte that BigInteger adds. */
  private static byte[] unsigned(BigInteger value) {
    byte[] bytes = value.toByteArray();
    return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
  }
}
