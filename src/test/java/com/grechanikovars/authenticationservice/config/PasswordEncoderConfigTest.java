package com.grechanikovars.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Checks the properties of the password encoder that the rest of the service relies on: the
 * column {@code password_hash} is 60 characters wide, and every hash has its own salt.
 */
class PasswordEncoderConfigTest {

  private static final String PASSWORD = "correct horse battery staple";

  private final PasswordEncoder encoder = new PasswordEncoderConfig().passwordEncoder();

  @Test
  void hashIsBcryptWithCostTenAndSixtyCharacters() {
    String hash = encoder.encode(PASSWORD);

    assertAll(
        () -> assertEquals(60, hash.length()),
        () -> assertTrue(hash.startsWith("$2a$10$")),
        () -> assertFalse(hash.contains(PASSWORD)));
  }

  @Test
  void hashMatchesOnlyTheOriginalPassword() {
    String hash = encoder.encode(PASSWORD);

    assertAll(
        () -> assertTrue(encoder.matches(PASSWORD, hash)),
        () -> assertFalse(encoder.matches("another password", hash)));
  }

  @Test
  void samePasswordGivesDifferentHashesBecauseEverySaltIsUnique() {
    String first = encoder.encode(PASSWORD);
    String second = encoder.encode(PASSWORD);

    assertAll(
        () -> assertNotEquals(first, second),
        () -> assertTrue(encoder.matches(PASSWORD, first)),
        () -> assertTrue(encoder.matches(PASSWORD, second)));
  }
}
