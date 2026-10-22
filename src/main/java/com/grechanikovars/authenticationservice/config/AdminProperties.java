package com.grechanikovars.authenticationservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings of the first admin, who is created at startup.
 *
 * <p>{@link #toString()} is overridden on purpose: the generated one would print the login and
 * the password.
 *
 * @param login the login (an email) of the admin; it comes from the environment variable
 *     {@code ADMIN_LOGIN}
 * @param password the raw password of the admin; it comes from the environment variable
 *     {@code ADMIN_PASSWORD}
 */
@ConfigurationProperties(prefix = "app.admin")
public record AdminProperties(String login, String password) {

  /**
   * Describes the settings without the login and the password.
   *
   * @return a fixed text
   */
  @Override
  public String toString() {
    return "AdminProperties[login=***, password=***]";
  }
}
