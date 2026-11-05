package com.innowise.authservice.client;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.http.Fault;
import com.innowise.authservice.config.InternalApiProperties;
import com.innowise.authservice.config.UserServiceClientConfig;
import com.innowise.authservice.config.UserServiceProperties;
import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.UserServiceTimeoutException;
import com.innowise.authservice.exception.UserServiceUnavailableException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.LocalDate;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.web.client.ResourceAccessException;

/**
 * Tests {@link UserServiceClient} against a WireMock server that plays the User Service: what it
 * sends (path, key, body) and what it makes of every kind of answer.
 *
 * <p>The timeouts of the shared client are generous on purpose: the first request to a cold
 * WireMock server (and a cold HTTP client) can take seconds on a busy machine, and a test that is
 * not about timeouts must never depend on how fast the machine is. A short timeout is used only
 * by the two tests of timeouts, and there the stub delay is ten times longer than the timeout,
 * so a slow machine cannot make them fail.
 *
 * <p>The profile id (31) is easy to tell from the other numbers of the test.
 */
class UserServiceClientTest {

  private static final String KEY = "test-internal-key";
  private static final UUID REGISTRATION_ID =
      UUID.fromString("0b9c4b5e-6f3e-4a56-9d3a-5f6f0d2a7c11");
  private static final String DELETE_PATH =
      "/internal/users/by-registration/0b9c4b5e-6f3e-4a56-9d3a-5f6f0d2a7c11";

  /** Never reached by a test that is not about timeouts. */
  private static final Duration GENEROUS_TIMEOUT = Duration.ofSeconds(10);

  /** The read timeout of the tests of timeouts; the stub delay is far above it. */
  private static final Duration SHORT_READ_TIMEOUT = Duration.ofMillis(300);

  /** The delay of a slow stub: ten times the short read timeout. */
  private static final int SLOW_ANSWER_MILLIS = 3000;
  private static final InternalUserRequest REQUEST = new InternalUserRequest(
      "Alice", "Smith", LocalDate.of(1990, 5, 17), "Alice@Example.com");

  private WireMockServer userService;
  private UserServiceClient client;

  @BeforeEach
  void setUp() {
    userService = new WireMockServer(options().dynamicPort());
    userService.start();
    client = clientFor(userService.baseUrl(), GENEROUS_TIMEOUT, GENEROUS_TIMEOUT);
  }

  @AfterEach
  void tearDown() {
    userService.stop();
  }

  private static UserServiceClient clientFor(String baseUri, Duration connectTimeout,
      Duration readTimeout) {
    return new UserServiceClient(new UserServiceClientConfig().userServiceRestClient(
        new UserServiceProperties(baseUri, connectTimeout, readTimeout),
        new InternalApiProperties(KEY)));
  }

  @Test
  void createSendsTheProfileWithTheKeyAndTheRegistrationIdAndReturnsTheStoredForm() {
    userService.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody("""
            {"id": 31, "name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
             "email": "alice@example.com", "active": true,
             "createdAt": "2026-10-31T10:00:00Z", "updatedAt": "2026-10-31T10:00:00Z"}
            """)));

    InternalUserResponse user = client.create(REQUEST, REGISTRATION_ID);

    assertAll(
        () -> assertEquals(31L, user.id()),
        () -> assertEquals("alice@example.com", user.email()),
        () -> assertEquals(LocalDate.of(1990, 5, 17), user.birthDate()),
        () -> userService.verify(postRequestedFor(urlEqualTo("/internal/users"))
            .withHeader("X-Internal-Key", equalTo(KEY))
            .withHeader("X-Registration-Id", equalTo(REGISTRATION_ID.toString()))
            .withHeader("Content-Type", equalTo("application/json"))
            .withRequestBody(equalToJson("""
                {"name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
                 "email": "Alice@Example.com"}
                """))));
  }

  @Test
  void aTakenEmailIsAConflict() {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(409)));

    assertThrows(EmailAlreadyRegisteredException.class,
        () -> client.create(REQUEST, REGISTRATION_ID));
  }

  /** A server error may come after the work was done (or from a proxy): the outcome is unknown. */
  @ParameterizedTest
  @ValueSource(ints = {500, 502, 503, 504})
  void aServerErrorIsUnavailableWithAnUnknownOutcome(int status) {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(status).withBody("secret details")));

    UserServiceUnavailableException error =
        assertThrows(UserServiceUnavailableException.class,
            () -> client.create(REQUEST, REGISTRATION_ID));

    assertAll(
        () -> assertEquals(UserServiceUnavailableException.MESSAGE, error.getMessage()),
        () -> assertTrue(error.isOutcomeUnknown()));
  }

  /** The User Service checks and rejects a request before it changes anything. */
  @ParameterizedTest
  @ValueSource(ints = {400, 401, 403})
  void aClientErrorIsUnavailableWithNothingCreated(int status) {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(status)));

    UserServiceUnavailableException error =
        assertThrows(UserServiceUnavailableException.class,
            () -> client.create(REQUEST, REGISTRATION_ID));

    assertFalse(error.isOutcomeUnknown());
  }

  /** The profile was created (201), so the outcome is unknown even though no id came back. */
  @Test
  void aCreatedAnswerWithoutAnIdIsUnavailableWithAnUnknownOutcome() {
    userService.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody("{\"email\": \"alice@example.com\"}")));

    UserServiceUnavailableException error =
        assertThrows(UserServiceUnavailableException.class,
            () -> client.create(REQUEST, REGISTRATION_ID));

    assertTrue(error.isOutcomeUnknown());
  }

  @Test
  void aBodyThatIsNotJsonIsUnavailableWithAnUnknownOutcome() {
    userService.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody("not json")));

    UserServiceUnavailableException error =
        assertThrows(UserServiceUnavailableException.class,
            () -> client.create(REQUEST, REGISTRATION_ID));

    assertTrue(error.isOutcomeUnknown());
  }

  /** The answer is lost in a moment, with no waiting: the connection breaks after the request. */
  @ParameterizedTest
  @EnumSource(value = Fault.class,
      names = {"CONNECTION_RESET_BY_PEER", "EMPTY_RESPONSE", "MALFORMED_RESPONSE_CHUNK"})
  void aBrokenConnectionIsUnavailableWithAnUnknownOutcome(Fault fault) {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withFault(fault)));

    UserServiceUnavailableException error =
        assertThrows(UserServiceUnavailableException.class,
            () -> client.create(REQUEST, REGISTRATION_ID));

    assertTrue(error.isOutcomeUnknown());
  }

  /** A timeout of the answer: the request was sent, so it may have been carried out. */
  @Test
  void aSlowAnswerIsATimeoutWithAnUnknownOutcome() {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(201).withFixedDelay(SLOW_ANSWER_MILLIS)));
    UserServiceClient impatient =
        clientFor(userService.baseUrl(), GENEROUS_TIMEOUT, SHORT_READ_TIMEOUT);

    UserServiceTimeoutException error = assertThrows(UserServiceTimeoutException.class,
        () -> impatient.create(REQUEST, REGISTRATION_ID));

    assertTrue(error.isOutcomeUnknown());
  }

  /** Nobody listens: the request never left, so nothing can have been created. */
  @Test
  void aServiceThatIsNotThereIsUnavailableWithNothingCreated() {
    String address = userService.baseUrl();
    userService.stop();

    UserServiceClient offline = clientFor(address, GENEROUS_TIMEOUT, GENEROUS_TIMEOUT);

    UserServiceUnavailableException error =
        assertThrows(UserServiceUnavailableException.class,
            () -> offline.create(REQUEST, REGISTRATION_ID));

    assertFalse(error.isOutcomeUnknown());
  }

  @Test
  void aConnectionThatCouldNotBeOpenedNeverSentTheRequest() {
    assertAll(
        () -> assertTrue(UserServiceClient.requestNeverSent(new ConnectException())),
        () -> assertTrue(UserServiceClient.requestNeverSent(
            new HttpConnectTimeoutException("connect timed out"))),
        () -> assertTrue(UserServiceClient.requestNeverSent(new UnknownHostException())),
        // The causes are searched too: the HTTP client wraps the failure.
        () -> assertTrue(UserServiceClient.requestNeverSent(
            new ResourceAccessException("I/O error", new ConnectException()))),
        () -> assertTrue(UserServiceClient.requestNeverSent(
            new IOException("wrapped", new HttpConnectTimeoutException("connect")))));
  }

  /** Every failure after the connection was open may have come after the work was done. */
  @Test
  void aFailureAfterTheConnectionWasOpenMayHaveSentTheRequest() {
    assertAll(
        () -> assertFalse(UserServiceClient.requestNeverSent(new IOException("reset"))),
        () -> assertFalse(UserServiceClient.requestNeverSent(
            new SocketTimeoutException("read timed out"))),
        () -> assertFalse(UserServiceClient.requestNeverSent(
            new HttpTimeoutException("request timed out"))),
        () -> assertFalse(UserServiceClient.requestNeverSent(
            new ResourceAccessException("I/O error", new IOException("reset")))));
  }

  @Test
  void deleteByRegistrationIdSendsTheKeyAndAcceptsNoContent() {
    userService.stubFor(delete(urlEqualTo(DELETE_PATH))
        .willReturn(aResponse().withStatus(204)));

    assertAll(
        () -> assertDoesNotThrow(() -> client.deleteByRegistrationId(REGISTRATION_ID)),
        () -> userService.verify(deleteRequestedFor(urlEqualTo(DELETE_PATH))
            .withHeader("X-Internal-Key", equalTo(KEY))));
  }

  /** A profile that does not exist makes the undoing safe to repeat (and safe when unneeded). */
  @Test
  void deleteOfAProfileThatDoesNotExistIsNotAnError() {
    userService.stubFor(delete(urlEqualTo(DELETE_PATH))
        .willReturn(aResponse().withStatus(404)));

    assertDoesNotThrow(() -> client.deleteByRegistrationId(REGISTRATION_ID));
  }

  @Test
  void deleteWithAnErrorStatusIsUnavailable() {
    userService.stubFor(delete(urlEqualTo(DELETE_PATH))
        .willReturn(aResponse().withStatus(500)));

    assertThrows(UserServiceUnavailableException.class,
        () -> client.deleteByRegistrationId(REGISTRATION_ID));
  }

  @Test
  void deleteThatIsTooSlowIsATimeout() {
    userService.stubFor(delete(urlEqualTo(DELETE_PATH))
        .willReturn(aResponse().withStatus(204).withFixedDelay(SLOW_ANSWER_MILLIS)));
    UserServiceClient impatient =
        clientFor(userService.baseUrl(), GENEROUS_TIMEOUT, SHORT_READ_TIMEOUT);

    assertThrows(UserServiceTimeoutException.class,
        () -> impatient.deleteByRegistrationId(REGISTRATION_ID));
  }

  /** A 401 means a wrong key: it must not be taken for "already gone". */
  @Test
  void deleteWithAWrongKeyIsUnavailable() {
    userService.stubFor(delete(urlEqualTo(DELETE_PATH))
        .willReturn(aResponse().withStatus(401)));

    assertThrows(UserServiceUnavailableException.class,
        () -> client.deleteByRegistrationId(REGISTRATION_ID));
  }
}
