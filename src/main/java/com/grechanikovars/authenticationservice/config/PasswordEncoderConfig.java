package com.grechanikovars.authenticationservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Provides the {@link PasswordEncoder} that hashes the passwords of the accounts.
 *
 * <p>The encoder is a plain {@link BCryptPasswordEncoder}, not the delegating encoder: the
 * {@code credentials.password_hash} column holds only BCrypt hashes (always 60 characters)
 * without an algorithm prefix. BCrypt generates a new random salt for every hash and keeps it
 * inside the hash, so two hashes of the same password differ and no separate salt column is
 * needed. The cost factor is the default one (10).
 */
@Configuration(proxyBeanMethods = false)
public class PasswordEncoderConfig {

  /**
   * Creates the password encoder.
   *
   * @return a BCrypt encoder with the default cost factor
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
