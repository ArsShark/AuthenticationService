package com.innowise.authservice.dto.request;

import com.innowise.authservice.validation.ValidPassword;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import java.time.LocalDate;

/**
 * The body of the public registration: the data of the profile and the password of the account.
 *
 * <p>The rules of the profile are those of the User Service and the rules of the password are
 * those of {@link CredentialRequest}, so a request that passes here is accepted by both steps of
 * the registration. They are checked first, because a refusal of the second step would mean that
 * the profile has to be created and removed again.
 *
 * <p>{@link #toString()} is overridden: the generated one would print the password and the
 * email.
 *
 * @param name the first name
 * @param surname the surname
 * @param birthDate the date of birth, in the past
 * @param email the email; it is also the login
 * @param password the raw password; it is never stored or logged
 */
public record RegisterRequest(
    @NotBlank @Size(max = 100) String name,
    @NotBlank @Size(max = 100) String surname,
    @NotNull @Past LocalDate birthDate,
    @NotBlank @Size(max = 255) @Email String email,
    @NotNull @ValidPassword String password) {

  /**
   * Describes the request without any of its values.
   *
   * @return a fixed text
   */
  @Override
  public String toString() {
    return "RegisterRequest[***]";
  }
}
