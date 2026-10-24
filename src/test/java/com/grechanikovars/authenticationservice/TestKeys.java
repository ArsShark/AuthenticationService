package com.grechanikovars.authenticationservice;

import com.grechanikovars.authenticationservice.security.JwtKeys;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * Keys for tests. No key is stored in the repository: one RSA key pair is generated when the
 * class is loaded and shared by all tests of the JVM.
 *
 * <p>Generating a 2048-bit RSA key takes a fraction of a second, so one shared pair keeps the
 * tests fast. Tests that need another key call {@link #generateRsa(int)}.
 */
public final class TestKeys {

  /** The key pair that the application uses in tests. */
  public static final KeyPair KEY_PAIR = generateRsa(2048);

  /** The private key of {@link #KEY_PAIR} as the application expects it in its settings. */
  public static final String PRIVATE_KEY_BASE64 = toPkcs8Base64(KEY_PAIR.getPrivate());

  private TestKeys() {
  }

  /**
   * Generates an RSA key pair.
   *
   * @param bits the length of the modulus
   * @return a new key pair
   */
  public static KeyPair generateRsa(int bits) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(bits);
      return generator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("The JDK has no RSA", e);
    }
  }

  /**
   * Encodes a private key like the environment variable {@code JWT_PRIVATE_KEY}: PKCS#8 DER,
   * base64 on one line.
   *
   * @param key a private key
   * @return the encoded key
   */
  public static String toPkcs8Base64(PrivateKey key) {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }

  /**
   * Reads {@link #PRIVATE_KEY_BASE64} the way the application does.
   *
   * @return the keys of the application in tests
   */
  public static JwtKeys jwtKeys() {
    return JwtKeys.fromPkcs8Base64(PRIVATE_KEY_BASE64);
  }
}
