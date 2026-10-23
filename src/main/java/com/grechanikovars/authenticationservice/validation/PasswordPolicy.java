package com.grechanikovars.authenticationservice.validation;

import java.nio.charset.StandardCharsets;

/**
 * The rules for a raw password, in one place for every caller: the registration request (through
 * {@link ValidPassword}) and the first admin that is created at startup.
 *
 * <p>A password must not be blank, must have at least {@value #MIN_LENGTH} characters and at most
 * {@value #MAX_BYTES} bytes in UTF-8. The upper limit is a BCrypt limit: BCrypt looks only at the
 * first 72 bytes, so a longer password would silently be cut. Characters are counted as Unicode
 * code points, bytes after the encoding. The password is never stripped: spaces are allowed.
 */
public final class PasswordPolicy {

  /** The minimum number of characters (code points). */
  public static final int MIN_LENGTH = 8;

  /** The maximum number of bytes in UTF-8, the input limit of BCrypt. */
  public static final int MAX_BYTES = 72;

  private PasswordPolicy() {
  }

  /**
   * Checks a raw password against the rules.
   *
   * @param password the raw password, may be {@code null}
   * @return {@code true} if the password follows the rules; {@code false} for {@code null}
   */
  public static boolean isValid(String password) {
    if (password == null || password.isBlank()) {
      return false;
    }
    int length = password.codePointCount(0, password.length());
    return length >= MIN_LENGTH && isWithinBcryptLimit(password);
  }

  /**
   * Tells whether BCrypt reads the whole password, that is, whether it has at most
   * {@value #MAX_BYTES} bytes in UTF-8.
   *
   * <p>A login uses this rule alone. It must not apply the rest of the policy, because a weak
   * password is simply a wrong one and gets the same answer. But it must apply this limit:
   * BCrypt cuts a longer password silently, so the text "the real password plus anything" would
   * match the hash of a password of exactly 72 bytes.
   *
   * @param password the raw password, may be {@code null}
   * @return {@code true} if the password has at most 72 bytes; {@code false} for {@code null}
   */
  public static boolean isWithinBcryptLimit(String password) {
    return password != null && password.getBytes(StandardCharsets.UTF_8).length <= MAX_BYTES;
  }
}
