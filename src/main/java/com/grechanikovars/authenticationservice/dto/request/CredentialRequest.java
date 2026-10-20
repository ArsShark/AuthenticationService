package com.grechanikovars.authenticationservice.dto.request;

import com.grechanikovars.authenticationservice.validation.ValidPassword;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/**
 * The body of the registration of an account. There is no role here: a registered account always
 * gets the role {@code USER}.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the password
 * and the login (an email) into any log that prints the request.
 *
 * @param login the email of the user
 * @param password the raw password, see {@link ValidPassword} for the rules
 * @param userId the id of the profile in User Service
 */
public record CredentialRequest(
    @NotBlank @Size(max = 255) @Email String login,
    @NotNull @ValidPassword String password,
    @NotNull @Positive Long userId) {

  /**
   * Describes the request without the password and without the login.
   *
   * @return a text with the user id only
   */
  @Override
  public String toString() {
    return String.format("CredentialRequest[userId=%s]", userId);
  }
}
