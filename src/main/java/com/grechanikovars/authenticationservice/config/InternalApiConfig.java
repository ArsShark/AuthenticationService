package com.grechanikovars.authenticationservice.config;

import com.grechanikovars.authenticationservice.security.InternalKeyInterceptor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Protects the internal endpoints ({@code /internal/**}) with the internal key.
 *
 * <p>The path prefix is not under {@code /api/auth/**} on purpose: that is the route the Gateway
 * will open to the outside, so an internal endpoint can never be reached through it.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(InternalApiProperties.class)
public class InternalApiConfig implements WebMvcConfigurer {

  private final InternalApiProperties properties;

  public InternalApiConfig(InternalApiProperties properties) {
    this.properties = properties;
  }

  /**
   * Registers the key check for the internal endpoints. A missing key stops the startup, because
   * the interceptor refuses it.
   */
  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(new InternalKeyInterceptor(properties.apiKey()))
        .addPathPatterns("/internal/**");
  }
}
