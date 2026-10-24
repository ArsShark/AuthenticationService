package com.grechanikovars.authenticationservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;

/**
 * Entry point of the Authentication Service.
 *
 * <p>{@link UserDetailsServiceAutoConfiguration} is excluded on purpose: it creates an in-memory
 * user with a random password and prints that password to the log. This service never
 * authenticates through Spring Security's username and password support; accounts live in the
 * database and are checked by our own code.
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class AuthenticationServiceApplication {

  public static void main(String[] args) {
    SpringApplication.run(AuthenticationServiceApplication.class, args);
  }

}
