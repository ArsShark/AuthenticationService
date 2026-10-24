package com.grechanikovars.authenticationservice.controller;

import com.grechanikovars.authenticationservice.security.JwksDocument;
import java.time.Duration;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the public key that verifies the tokens of this service.
 *
 * <p>The endpoint is public, because the key is. It is not under {@code /api}: the Gateway routes
 * only {@code /api/**} to the outside, so the key is read by the other services from the internal
 * address of this one and is not part of the public API.
 */
@RestController
public class JwksController {

  /** The standard place of a JSON Web Key Set (RFC 8615: the {@code .well-known} prefix). */
  static final String PATH = "/.well-known/jwks.json";

  /**
   * How long a client may reuse the answer. The key does not change while the service runs, but
   * a new deployment may bring a new key, and five minutes keep clients from using a stale one
   * for long.
   */
  private static final CacheControl CACHE =
      CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic();

  private final JwksDocument document;

  public JwksController(JwksDocument document) {
    this.document = document;
  }

  /**
   * Returns the JSON Web Key Set.
   *
   * <p>The content type is set explicitly to {@code application/json}, which every client reads.
   * The caching header is set here and not left to Spring Security: Security adds its own
   * {@code no-store} header only when none is present.
   *
   * @return 200 with the key set; it is cacheable by anybody for five minutes
   */
  @GetMapping(PATH)
  public ResponseEntity<Map<String, Object>> jwks() {
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_JSON)
        .cacheControl(CACHE)
        .body(document.jwkSet());
  }
}
