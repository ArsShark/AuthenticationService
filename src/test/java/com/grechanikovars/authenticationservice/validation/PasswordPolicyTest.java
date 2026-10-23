package com.grechanikovars.authenticationservice.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;

/**
 * Checks the boundaries of {@link PasswordPolicy}: the minimum in characters, the maximum in
 * bytes.
 *
 * <p>Non-ASCII characters are written as Unicode escapes: {@code \u00e9} is two bytes in UTF-8,
 * {@code \uD83D\uDE00} (a smiley) is one code point, two UTF-16 units and four bytes.
 */
class PasswordPolicyTest {

  private static final String TWO_BYTE_CHAR = "\u00e9";
  private static final String FOUR_BYTE_CHAR = "\uD83D\uDE00";

  @ParameterizedTest
  @MethodSource("validPasswords")
  void acceptsPasswordsInsideTheLimits(String password) {
    assertTrue(PasswordPolicy.isValid(password));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @MethodSource("invalidPasswords")
  void rejectsPasswordsOutsideTheLimits(String password) {
    assertFalse(PasswordPolicy.isValid(password));
  }

  /** A login applies only the byte limit, so short and even empty passwords are not cut off. */
  @ParameterizedTest
  @MethodSource("passwordsBcryptReadsWhole")
  void bcryptLimitAcceptsEverythingUpToSeventyTwoBytes(String password) {
    assertTrue(PasswordPolicy.isWithinBcryptLimit(password));
  }

  @ParameterizedTest
  @NullSource
  @MethodSource("passwordsBcryptWouldCut")
  void bcryptLimitRejectsWhatBcryptWouldSilentlyCut(String password) {
    assertFalse(PasswordPolicy.isWithinBcryptLimit(password));
  }

  static Stream<String> passwordsBcryptReadsWhole() {
    return Stream.of(
        "",
        "a",
        "a".repeat(72),
        TWO_BYTE_CHAR.repeat(36),
        FOUR_BYTE_CHAR.repeat(18));
  }

  static Stream<String> passwordsBcryptWouldCut() {
    return Stream.of(
        "a".repeat(73),
        TWO_BYTE_CHAR.repeat(36).concat("a"),
        FOUR_BYTE_CHAR.repeat(19));
  }

  static Stream<String> validPasswords() {
    return Stream.of(
        "12345678",
        "a".repeat(72),
        TWO_BYTE_CHAR.repeat(36),
        FOUR_BYTE_CHAR.repeat(8),
        "correct horse battery staple",
        "  spaces are kept  ");
  }

  static Stream<String> invalidPasswords() {
    return Stream.of(
        "1234567",
        "a".repeat(73),
        TWO_BYTE_CHAR.repeat(36).concat("a"),
        FOUR_BYTE_CHAR.repeat(4),
        " ".repeat(8));
  }
}
