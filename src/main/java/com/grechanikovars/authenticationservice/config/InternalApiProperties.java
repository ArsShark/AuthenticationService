package com.grechanikovars.authenticationservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings of the internal endpoints, the ones that only other services may call.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the key.
 *
 * @param apiKey the shared key that callers send in the header {@code X-Internal-Key}; it comes
 *     from the environment variable {@code INTERNAL_API_KEY} and has no default
 */
@ConfigurationProperties(prefix = "app.internal")
public record InternalApiProperties(String apiKey) {

  /**
   * Describes the settings without the key.
   *
   * @return a fixed text
   */
  @Override
  public String toString() {
    return "InternalApiProperties[apiKey=***]";
  }
}
