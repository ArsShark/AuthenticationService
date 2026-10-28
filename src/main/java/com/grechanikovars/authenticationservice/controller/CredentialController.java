package com.grechanikovars.authenticationservice.controller;

import com.grechanikovars.authenticationservice.dto.request.CredentialRequest;
import com.grechanikovars.authenticationservice.dto.response.CredentialResponse;
import com.grechanikovars.authenticationservice.service.CredentialService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The internal endpoint that creates accounts. It is called by the Gateway during the
 * registration of a user, and it is protected by the internal key, not by a user token.
 *
 * <p>The path is under {@code /internal}, not under {@code /api/auth}: the route that the Gateway
 * opens to the outside can never reach it.
 */
@RestController
@RequestMapping("/internal/credentials")
public class CredentialController {

  private final CredentialService credentialService;

  public CredentialController(CredentialService credentialService) {
    this.credentialService = credentialService;
  }

  /**
   * Registers an account with the role {@code USER}.
   *
   * <p>There is no {@code Location} header: accounts cannot be read by id, and the response never
   * holds the password hash.
   *
   * @param request the login, the password and the id of the profile in User Service
   * @return 201 with the public view of the new account; 400 for an invalid body, 401 for a wrong
   *     internal key, 409 for a taken login or a user that already has an account
   */
  @PostMapping
  public ResponseEntity<CredentialResponse> register(
      @Valid @RequestBody CredentialRequest request) {
    CredentialResponse response =
        credentialService.register(request.login(), request.password(), request.userId());
    return ResponseEntity.status(HttpStatus.CREATED).body(response);
  }

  /**
   * Deletes the account of a user profile. It undoes {@link #register}: the Gateway calls it when
   * a registration fails after the profile was created, and again, safely, when it does not know
   * whether the account was created.
   *
   * @param userId the id of the profile in User Service
   * @return 204 when the account was deleted; 401 for a wrong internal key; 404 when the profile
   *     has no account (for example because the call is a repetition)
   */
  @DeleteMapping("/by-user/{userId}")
  public ResponseEntity<Void> deleteByUserId(@PathVariable Long userId) {
    credentialService.deleteByUserId(userId);
    return ResponseEntity.noContent().build();
  }
}
