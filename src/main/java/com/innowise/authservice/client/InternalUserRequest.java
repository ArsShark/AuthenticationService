package com.innowise.authservice.client;

import java.time.LocalDate;

/**
 * The body of {@code POST /internal/users} of the User Service: the profile to create.
 *
 * <p>{@link #toString()} is overridden: the generated one would print the name and the email.
 *
 * @param name the first name
 * @param surname the surname
 * @param birthDate the date of birth
 * @param email the email
 */
public record InternalUserRequest(String name, String surname, LocalDate birthDate,
    String email) {

  /**
   * Describes the request without any of its values.
   *
   * @return a fixed text
   */
  @Override
  public String toString() {
    return "InternalUserRequest[***]";
  }
}
