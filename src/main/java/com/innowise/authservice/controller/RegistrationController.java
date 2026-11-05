package com.innowise.authservice.controller;

import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.service.RegistrationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The public registration of a new user.
 *
 * <p>The endpoint is open to everybody, like the login: the caller has no account yet. The
 * logic, including the undoing of a failed registration, is in {@link RegistrationService}.
 */
@RestController
@RequestMapping("/api/auth")
public class RegistrationController {

  private final RegistrationService registrationService;

  public RegistrationController(RegistrationService registrationService) {
    this.registrationService = registrationService;
  }

  /**
   * Registers a user: creates the profile and the account with the role {@code USER}.
   *
   * <p>There is no token in the answer: the user logs in next.
   *
   * @param request the profile data and the password
   * @return 201 with the new profile; 400 for an invalid body; 409 if the email is taken; 502 or
   *     504 if the User Service cannot be reached or does not answer in time
   */
  @PostMapping("/register")
  public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
    return ResponseEntity.status(HttpStatus.CREATED).body(registrationService.register(request));
  }
}
