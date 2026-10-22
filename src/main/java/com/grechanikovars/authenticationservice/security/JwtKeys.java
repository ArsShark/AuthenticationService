package com.grechanikovars.authenticationservice.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * The RSA key pair that signs and verifies the tokens, and the id of the public key.
 *
 * <p>Only the private key is configured. The public key is derived from it, so the two can never
 * be out of step, and the id ({@code kid}) is the RFC 7638 thumbprint of the public key, so it
 * changes exactly when the key changes.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the key.
 *
 * @param privateKey the key that signs tokens
 * @param publicKey the key that verifies tokens; it is published as a JWK
 * @param keyId the {@code kid} of the public key: the base64url SHA-256 thumbprint
 */
public record JwtKeys(RSAPrivateKey privateKey, RSAPublicKey publicKey, String keyId) {

  /** The shortest accepted modulus. RSA keys below 2048 bits are not considered safe. */
  static final int MIN_MODULUS_BITS = 2048;

  private static final String NOT_SET = "JWT_PRIVATE_KEY is not set";
  private static final String NOT_BASE64 = "JWT_PRIVATE_KEY is not valid base64 on one line";
  private static final String NOT_PKCS8_RSA =
      "JWT_PRIVATE_KEY is not an RSA private key in PKCS#8 DER format (see the README)";
  private static final String NOT_CRT =
      "JWT_PRIVATE_KEY must hold the CRT parameters of the RSA key (the public key is derived)";
  private static final String TOO_SHORT =
      String.format("JWT_PRIVATE_KEY must be an RSA key of at least %d bits", MIN_MODULUS_BITS);

  /**
   * Reads the private key and derives the public key and the key id from it.
   *
   * <p>None of the error messages contains the value or a part of it, because the value is a
   * secret and the messages end up in the log.
   *
   * @param base64 an RSA private key in PKCS#8 DER format, encoded as base64 on one line;
   *     surrounding whitespace is ignored
   * @return the key pair and the key id
   * @throws IllegalStateException if the value is empty, is not base64, is not an RSA PKCS#8
   *     key, has no CRT parameters or is shorter than 2048 bits
   */
  public static JwtKeys fromPkcs8Base64(String base64) {
    if (base64 == null || base64.isBlank()) {
      throw new IllegalStateException(NOT_SET);
    }
    byte[] der = decode(base64.strip());
    try {
      KeyFactory factory = KeyFactory.getInstance("RSA");
      PrivateKey parsed = factory.generatePrivate(new PKCS8EncodedKeySpec(der));
      if (!(parsed instanceof RSAPrivateCrtKey privateKey)) {
        throw new IllegalStateException(NOT_CRT);
      }
      if (privateKey.getModulus().bitLength() < MIN_MODULUS_BITS) {
        throw new IllegalStateException(TOO_SHORT);
      }
      RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
          new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
      return new JwtKeys(privateKey, publicKey, thumbprint(publicKey));
    } catch (GeneralSecurityException e) {
      // The cause is dropped on purpose: parser messages must not be able to carry key bytes.
      throw new IllegalStateException(NOT_PKCS8_RSA);
    }
  }

  private static byte[] decode(String base64) {
    try {
      return Base64.getDecoder().decode(base64);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(NOT_BASE64);
    }
  }

  private static String thumbprint(RSAPublicKey publicKey) {
    try {
      return new RSAKey.Builder(publicKey).build().computeThumbprint().toString();
    } catch (JOSEException e) {
      throw new IllegalStateException("Cannot compute the id of the public key", e);
    }
  }

  /**
   * Describes the key pair without the private key.
   *
   * @return the key id and a mask in place of the private key
   */
  @Override
  public String toString() {
    return String.format("JwtKeys[keyId=%s, privateKey=***]", keyId);
  }
}
