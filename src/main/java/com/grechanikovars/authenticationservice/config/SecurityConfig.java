package com.grechanikovars.authenticationservice.config;

import com.grechanikovars.authenticationservice.security.ProblemDetailSecurityHandler;
import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Spring Security setup of the Authentication Service: a stateless chain that is closed by
 * default.
 *
 * <p>The service is an API for other programs, so there are no sessions, no CSRF protection (it
 * protects cookie sessions, and there are none), no login form, no HTTP Basic and no logout
 * page. Every request that no rule opens is denied, so an unknown path is answered by Security
 * and never reaches Spring MVC: an anonymous caller gets 401, an authenticated one 403.
 *
 * <p>Both answers are written as {@code ProblemDetail} by {@link ProblemDetailSecurityHandler}.
 *
 * <p>The ERROR dispatch is permitted: when the servlet container forwards a failed request to the
 * error page, that internal forward must not be denied again, otherwise the client would see
 * 401 or 403 instead of the real status. A direct request to {@code /error} is a normal REQUEST
 * dispatch and stays closed.
 *
 * <p>{@code /internal/**} is open here only because
 * {@link com.grechanikovars.authenticationservice.security.InternalKeyInterceptor} still checks
 * the internal key; a Security filter takes over that check and this rule is tightened then.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

  /**
   * Builds the one security filter chain of the service.
   *
   * @param http the builder provided by Spring Security
   * @param resolver the exception resolver of Spring MVC; the name is needed because Spring Boot
   *     has more than one bean of this type
   * @return the chain that handles every request
   * @throws Exception if Spring Security cannot build the chain
   */
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http,
      @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver)
      throws Exception {
    ProblemDetailSecurityHandler errorHandler = new ProblemDetailSecurityHandler(resolver);
    return http
        .csrf(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .exceptionHandling(handling -> handling
            .authenticationEntryPoint(errorHandler)
            .accessDeniedHandler(errorHandler))
        .authorizeHttpRequests(requests -> requests
            .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
            .requestMatchers("/internal/**").permitAll()
            .anyRequest().denyAll())
        .build();
  }
}
