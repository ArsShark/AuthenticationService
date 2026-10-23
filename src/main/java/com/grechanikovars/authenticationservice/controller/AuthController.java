package com.grechanikovars.authenticationservice.controller;

import com.grechanikovars.authenticationservice.dto.request.LoginRequest;
import com.grechanikovars.authenticationservice.dto.response.TokenResponse;
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
}
