package com.innowise.authservice.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.LocalDate;

/**
 * The part of the answer of {@code POST /internal/users} that this service uses; the other
 * fields of the answer are ignored.
 *
 * <p>{@link #toString()} is overridden: the generated one would print the name and the email.
 *
 * @param id the id of the new profile
 * @param name the first name
 * @param surname the surname
 * @param birthDate the date of birth
 * @param email the email in the form in which the User Service stored it (stripped, lowercase)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record InternalUserResponse(Long id, String name, String surname, LocalDate birthDate,
    String email) {

  /**
   * Describes the answer without the personal data.
   *
   * @return the id only
   */
  @Override
  public String toString() {
    return String.format("InternalUserResponse[id=%s]", id);
  }
}
