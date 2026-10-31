package com.innowise.authservice.client;

import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.UserServiceTimeoutException;
import com.innowise.authservice.exception.UserServiceUnavailableException;
import java.net.SocketTimeoutException;
import java.net.http.HttpTimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

/**
 * Calls the internal endpoints of the User Service: creates a profile and removes it again.
 *
 * <p>What goes wrong is turned into three exceptions, so the registration does not depend on
 * HTTP details: a taken email is {@link EmailAlreadyRegisteredException}, a call that ran out of
 * time is {@link UserServiceTimeoutException}, and anything else (no connection, an error status,
 * an unreadable body) is {@link UserServiceUnavailableException}. The cause is logged with the
 * class name or the status only: the messages of the HTTP client hold the address of the service,
 * and a body can hold an email.
 */
@Component
public class UserServiceClient {

  private static final Logger LOGGER = LoggerFactory.getLogger(UserServiceClient.class);

  private final RestClient restClient;

  public UserServiceClient(@Qualifier("userServiceRestClient") RestClient restClient) {
    this.restClient = restClient;
  }

  /**
   * Creates a profile ({@code POST /internal/users}).
   *
   * @param request the data of the profile
   * @return the new profile, with its id and the email as the User Service stored it
   * @throws EmailAlreadyRegisteredException if the User Service answers 409
   * @throws UserServiceTimeoutException if the call ran out of time
   * @throws UserServiceUnavailableException for every other failure
   */
  public InternalUserResponse create(InternalUserRequest request) {
    InternalUserResponse user;
    try {
      user = restClient.post()
          .uri("/internal/users")
          .contentType(MediaType.APPLICATION_JSON)
          .body(request)
          .retrieve()
          .body(InternalUserResponse.class);
    } catch (RestClientException e) {
      throw translate(e, true);
    }
    if (user == null || user.id() == null || user.email() == null) {
      LOGGER.error("The user service created a profile but the answer has no id or email");
      throw new UserServiceUnavailableException();
    }
    return user;
  }

  /**
   * Removes a profile ({@code DELETE /internal/users/{id}}). A profile that is already gone
   * (404) is not an error: the call can be repeated safely.
   *
   * @param id the id of the profile
   * @throws UserServiceTimeoutException if the call ran out of time
   * @throws UserServiceUnavailableException for every other failure
   */
  public void delete(Long id) {
    try {
      restClient.delete()
          .uri("/internal/users/{id}", id)
          .retrieve()
          .toBodilessEntity();
    } catch (HttpClientErrorException.NotFound e) {
      LOGGER.info("Profile {} was already gone", id);
    } catch (RestClientException e) {
      throw translate(e, false);
    }
  }

  private static RuntimeException translate(RestClientException error, boolean creating) {
    if (error instanceof RestClientResponseException response) {
      int status = response.getStatusCode().value();
      if (creating && status == HttpStatus.CONFLICT.value()) {
        return new EmailAlreadyRegisteredException();
      }
      LOGGER.error("The user service answered with status {}", status);
      return new UserServiceUnavailableException();
    }
    if (error instanceof ResourceAccessException access && isTimeout(access)) {
      LOGGER.warn("The call to the user service ran out of time ({})", rootClass(access));
      return new UserServiceTimeoutException();
    }
    LOGGER.error("The call to the user service failed ({})", rootClass(error));
    return new UserServiceUnavailableException();
  }

  private static boolean isTimeout(ResourceAccessException error) {
    for (Throwable cause = error.getCause(); cause != null; cause = cause.getCause()) {
      if (cause instanceof HttpTimeoutException || cause instanceof SocketTimeoutException) {
        return true;
      }
    }
    return false;
  }

  private static String rootClass(Throwable error) {
    Throwable root = error;
    while (root.getCause() != null && root.getCause() != root) {
      root = root.getCause();
    }
    return root.getClass().getSimpleName();
  }
}
