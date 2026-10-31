package com.innowise.authservice.dto.response;

import java.time.LocalDate;

/**
 * The answer to a successful registration: the new profile. There is no token: the user logs in
 * next.
 *
 * @param id the id of the profile in the User Service
 * @param name the first name
 * @param surname the surname
 * @param birthDate the date of birth
 * @param email the email in the form in which it is stored (stripped, lowercase)
 */
public record RegisterResponse(Long id, String name, String surname, LocalDate birthDate,
    String email) {
}
