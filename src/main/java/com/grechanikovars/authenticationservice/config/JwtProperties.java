package com.grechanikovars.authenticationservice.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings of the tokens: the signing key, the lifetimes and the issuer.
 *
 * <p>The key is not checked here: {@code JwtKeys.fromPkcs8Base64} does that and fails the
 * startup with a message that never contains the key. The lifetimes and the issuer are checked
 * when the settings are bound, so a wrong value also stops the startup.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the key.
 *
 * @param privateKey the RSA private key, PKCS#8 DER in base64 on one line; it comes from the
 *     environment variable {@code JWT_PRIVATE_KEY} and has no default
 * @param accessTtl the lifetime of an access token ({@code JWT_ACCESS_TTL}, default 15 minutes)
 * @param refreshTtl the lifetime of a refresh token ({@code JWT_REFRESH_TTL}, default 7 days)
 * @param issuer the value of the {@code iss} claim ({@code JWT_ISSUER}); services that verify the
 *     tokens must expect the same value
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
    String privateKey, Duration accessTtl, Duration refreshTtl, String issuer) {

  /**
   * Checks the lifetimes and the issuer.
   *
   * @throws IllegalArgumentException if a lifetime is missing or not positive, if the refresh
   *     token does not live longer than the access token, or if the issuer is blank
   */
  public JwtProperties {
    requirePositive(accessTtl, "app.jwt.access-ttl");
    requirePositive(refreshTtl, "app.jwt.refresh-ttl");
    if (refreshTtl.compareTo(accessTtl) <= 0) {
      throw new IllegalArgumentException(
          "app.jwt.refresh-ttl must be longer than app.jwt.access-ttl");
    }
    if (issuer == null || issuer.isBlank()) {
      throw new IllegalArgumentException("app.jwt.issuer must not be blank");
    }
  }

  private static void requirePositive(Duration value, String name) {
    if (value == null || value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(String.format("%s must be a positive duration", name));
    }
  }

  /**
   * Describes the settings without the key.
   *
   * @return the lifetimes and the issuer, and a mask in place of the key
   */
  @Override
  public String toString() {
    return String.format("JwtProperties[privateKey=***, accessTtl=%s, refreshTtl=%s, issuer=%s]",
        accessTtl, refreshTtl, issuer);
  }
}
