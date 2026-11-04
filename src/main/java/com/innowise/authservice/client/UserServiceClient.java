package com.innowise.authservice.client;

import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.UserServiceCallException;
import com.innowise.authservice.exception.UserServiceTimeoutException;
import com.innowise.authservice.exception.UserServiceUnavailableException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.util.UUID;
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
 * <p>Every creation carries a registration id, a random UUID chosen by the caller for one
 * attempt to register ({@code X-Registration-Id}). The User Service stores it with the profile,
 * so the profile of an attempt can be removed by that id even when the answer of the creation was
 * lost and the id of the profile is not known.
 *
 * <p>What goes wrong is turned into three exceptions, so the registration does not depend on
 * HTTP details: a taken email is {@link EmailAlreadyRegisteredException}, a call that ran out of
 * time is {@link UserServiceTimeoutException}, and anything else (no connection, an error status,
 * an unreadable body) is {@link UserServiceUnavailableException}. The cause is logged with the
 * class name or the status only: the messages of the HTTP client hold the address of the service,
 * and a body can hold an email.
 *
 * <p>Both exceptions also say whether the User Service may have carried the request out
 * ({@link UserServiceCallException#isOutcomeUnknown()}). It certainly did not when the connection
 * could not be opened or when it answered with a client error (4xx: it checks and rejects a
 * request before it changes anything). In every other case the answer may have been lost after
 * the work was done: a timeout of the answer, a connection that broke, a 5xx (also from a proxy
 * in front of the service), and a successful answer that cannot be read or has no id.
 */
@Component
public class UserServiceClient {

  /** The header with the registration id of the creation. */
  public static final String REGISTRATION_ID_HEADER = "X-Registration-Id";

  private static final Logger LOGGER = LoggerFactory.getLogger(UserServiceClient.class);

  private final RestClient restClient;

  public UserServiceClient(@Qualifier("userServiceRestClient") RestClient restClient) {
    this.restClient = restClient;
  }

  /**
   * Creates a profile ({@code POST /internal/users}).
   *
   * @param request the data of the profile
   * @param registrationId the id of this attempt to register; the profile can be removed by it
   * @return the new profile, with its id and the email as the User Service stored it
   * @throws EmailAlreadyRegisteredException if the User Service answers 409
   * @throws UserServiceTimeoutException if the call ran out of time
   * @throws UserServiceUnavailableException for every other failure
   * @see UserServiceCallException#isOutcomeUnknown()
   */
  public InternalUserResponse create(InternalUserRequest request, UUID registrationId) {
    InternalUserResponse user;
    try {
      user = restClient.post()
          .uri("/internal/users")
          .header(REGISTRATION_ID_HEADER, registrationId.toString())
          .contentType(MediaType.APPLICATION_JSON)
          .body(request)
          .retrieve()
          .body(InternalUserResponse.class);
    } catch (RestClientException e) {
      throw translate(e, true);
    }
    if (user == null || user.id() == null || user.email() == null) {
      LOGGER.error("The user service created a profile but the answer has no id or email");
      throw new UserServiceUnavailableException(true);
    }
    return user;
  }

  /**
   * Removes the profile that was created with this registration id
   * ({@code DELETE /internal/users/by-registration/{registrationId}}). A profile that does not
   * exist (404) is not an error: the creation may never have happened, or the profile is already
   * gone, so the call can be repeated safely. Only the profile of that one attempt is affected,
   * never another profile with the same email.
   *
   * @param registrationId the id sent with the creation
   * @throws UserServiceTimeoutException if the call ran out of time
   * @throws UserServiceUnavailableException for every other failure
   */
  public void deleteByRegistrationId(UUID registrationId) {
    try {
      restClient.delete()
          .uri("/internal/users/by-registration/{registrationId}", registrationId)
          .retrieve()
          .toBodilessEntity();
    } catch (HttpClientErrorException.NotFound e) {
      LOGGER.info("No profile exists for registration {}", registrationId);
    } catch (RestClientException e) {
      throw translate(e, false);
    }
  }

  private static UserServiceCallException translate(RestClientException error,
      boolean creating) {
    if (error instanceof RestClientResponseException response) {
      int status = response.getStatusCode().value();
      if (creating && status == HttpStatus.CONFLICT.value()) {
        throw new EmailAlreadyRegisteredException();
      }
      LOGGER.error("The user service answered with status {}", status);
      return new UserServiceUnavailableException(!response.getStatusCode().is4xxClientError());
    }
    boolean neverSent = requestNeverSent(error);
    if (error instanceof ResourceAccessException access && isTimeout(access)) {
      LOGGER.warn("The call to the user service ran out of time ({})", rootClass(access));
      return new UserServiceTimeoutException(!neverSent);
    }
    LOGGER.error("The call to the user service failed ({})", rootClass(error));
    return new UserServiceUnavailableException(!neverSent);
  }

  /**
   * Tells whether a failed call certainly never reached the User Service: the connection could
   * not be opened (refused, timed out, unknown host). Any other failure of the transport may have
   * come after the request was sent and processed.
   *
   * @param error the failure of the call; its causes are searched too
   */
  static boolean requestNeverSent(Throwable error) {
    for (Throwable cause = error; cause != null; cause = cause.getCause()) {
      if (cause instanceof ConnectException
          || cause instanceof HttpConnectTimeoutException
          || cause instanceof UnknownHostException) {
        return true;
      }
    }
    return false;
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
