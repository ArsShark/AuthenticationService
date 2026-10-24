package com.grechanikovars.authenticationservice.controller;

import com.grechanikovars.authenticationservice.dto.request.LoginRequest;
import com.grechanikovars.authenticationservice.dto.request.RefreshRequest;
import com.grechanikovars.authenticationservice.dto.request.ValidateRequest;
import com.grechanikovars.authenticationservice.dto.response.TokenResponse;
import com.grechanikovars.authenticationservice.dto.response.ValidationResponse;
import com.grechanikovars.authenticationservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The public endpoints that hand out tokens. They are reached through the Gateway, which routes
 * {@code /api/auth/**} to this service.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  /**
   * Logs a user in.
   *
   * <p>The response is never cached: Spring Security adds {@code Cache-Control: no-store}, as RFC
   * 6749 asks for a response that holds tokens.
   *
   * @param request the login and the password
   * @return 200 with the access token and the refresh token; 400 for a malformed body; 401, the
   *     same for an unknown login and a wrong password
   */
  @PostMapping("/login")
  public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
    return ResponseEntity.ok(
        TokenResponse.from(authService.login(request.login(), request.password())));
  }

  /**
   * Exchanges a refresh token for a new pair of tokens. The used refresh token stops working.
   *
   * <p>The response is never cached, for the same reason as the one of the login.
   *
   * @param request the refresh token
   * @return 200 with the new access token and refresh token; 400 for a malformed body; 401, the
   *     same for every token that cannot be used
   */
  @PostMapping("/refresh")
  public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
    return ResponseEntity.ok(TokenResponse.from(authService.refresh(request.refreshToken())));
  }

  /**
   * Tells whether an access token is valid and who it belongs to.
   *
   * <p>A token that is not valid is a normal answer, not an error: the status is 200 and the
   * body is {@code {"valid": false}}, with no reason. Only a request without a token is refused.
   *
   * @param request the access token to check
   * @return 200 with the validity and, for a valid token, the user, the role and the expiry; 400
   *     for a malformed body
   */
  @PostMapping("/validate")
  public ResponseEntity<ValidationResponse> validate(@Valid @RequestBody ValidateRequest request) {
    return ResponseEntity.ok(authService.validate(request.token())
        .map(ValidationResponse::of)
        .orElseGet(ValidationResponse::invalid));
  }
}
