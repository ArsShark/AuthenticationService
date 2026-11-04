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
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.innowise.authservice.config.InternalApiProperties;
import com.innowise.authservice.config.UserServiceClientConfig;
import com.innowise.authservice.config.UserServiceProperties;
import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.UserServiceTimeoutException;
import com.innowise.authservice.exception.UserServiceUnavailableException;
import java.time.Duration;
import java.time.LocalDate;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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

  @Test
  void anErrorStatusIsUnavailable() {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(500).withBody("secret details")));

    UserServiceUnavailableException error =
        assertThrows(UserServiceUnavailableException.class,
            () -> client.create(REQUEST, REGISTRATION_ID));

    assertEquals(UserServiceUnavailableException.MESSAGE, error.getMessage());
  }

  @Test
  void aBadRequestIsUnavailableToo() {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(400)));

    assertThrows(UserServiceUnavailableException.class,
        () -> client.create(REQUEST, REGISTRATION_ID));
  }

  @Test
  void aCreatedAnswerWithoutAnIdIsUnavailable() {
    userService.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody("{\"email\": \"alice@example.com\"}")));

    assertThrows(UserServiceUnavailableException.class,
        () -> client.create(REQUEST, REGISTRATION_ID));
  }

  @Test
  void aBodyThatIsNotJsonIsUnavailable() {
    userService.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody("not json")));

    assertThrows(UserServiceUnavailableException.class,
        () -> client.create(REQUEST, REGISTRATION_ID));
  }

  @Test
  void aSlowAnswerIsATimeout() {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(201).withFixedDelay(SLOW_ANSWER_MILLIS)));
    UserServiceClient impatient =
        clientFor(userService.baseUrl(), GENEROUS_TIMEOUT, SHORT_READ_TIMEOUT);

    assertThrows(UserServiceTimeoutException.class,
        () -> impatient.create(REQUEST, REGISTRATION_ID));
  }

  @Test
  void aServiceThatIsNotThereIsUnavailable() {
    String address = userService.baseUrl();
    userService.stop();

    UserServiceClient offline = clientFor(address, GENEROUS_TIMEOUT, GENEROUS_TIMEOUT);

    assertThrows(UserServiceUnavailableException.class,
        () -> offline.create(REQUEST, REGISTRATION_ID));
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
