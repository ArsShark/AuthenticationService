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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests {@link UserServiceClient} against a WireMock server that plays the User Service: what it
 * sends (path, key, body) and what it makes of every kind of answer.
 *
 * <p>The profile id (31) is easy to tell from the other numbers of the test.
 */
class UserServiceClientTest {

  private static final String KEY = "test-internal-key";
  private static final InternalUserRequest REQUEST = new InternalUserRequest(
      "Alice", "Smith", LocalDate.of(1990, 5, 17), "Alice@Example.com");

  private WireMockServer userService;
  private UserServiceClient client;

  @BeforeEach
  void setUp() {
    userService = new WireMockServer(options().dynamicPort());
    userService.start();
    client = clientFor(userService.baseUrl(), Duration.ofMillis(500));
  }

  @AfterEach
  void tearDown() {
    userService.stop();
  }

  private static UserServiceClient clientFor(String baseUri, Duration readTimeout) {
    return new UserServiceClient(new UserServiceClientConfig().userServiceRestClient(
        new UserServiceProperties(baseUri, Duration.ofSeconds(1), readTimeout),
        new InternalApiProperties(KEY)));
  }

  @Test
  void createSendsTheProfileWithTheKeyAndReturnsTheStoredForm() {
    userService.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody("""
            {"id": 31, "name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
             "email": "alice@example.com", "active": true,
             "createdAt": "2026-10-31T10:00:00Z", "updatedAt": "2026-10-31T10:00:00Z"}
            """)));

    InternalUserResponse user = client.create(REQUEST);

    assertAll(
        () -> assertEquals(31L, user.id()),
        () -> assertEquals("alice@example.com", user.email()),
        () -> assertEquals(LocalDate.of(1990, 5, 17), user.birthDate()),
        () -> userService.verify(postRequestedFor(urlEqualTo("/internal/users"))
            .withHeader("X-Internal-Key", equalTo(KEY))
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

    assertThrows(EmailAlreadyRegisteredException.class, () -> client.create(REQUEST));
  }

  @Test
  void anErrorStatusIsUnavailable() {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(500).withBody("secret details")));

    UserServiceUnavailableException error =
        assertThrows(UserServiceUnavailableException.class, () -> client.create(REQUEST));

    assertEquals(UserServiceUnavailableException.MESSAGE, error.getMessage());
  }

  @Test
  void aBadRequestIsUnavailableToo() {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(400)));

    assertThrows(UserServiceUnavailableException.class, () -> client.create(REQUEST));
  }

  @Test
  void aCreatedAnswerWithoutAnIdIsUnavailable() {
    userService.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody("{\"email\": \"alice@example.com\"}")));

    assertThrows(UserServiceUnavailableException.class, () -> client.create(REQUEST));
  }

  @Test
  void aBodyThatIsNotJsonIsUnavailable() {
    userService.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody("not json")));

    assertThrows(UserServiceUnavailableException.class, () -> client.create(REQUEST));
  }

  @Test
  void aSlowAnswerIsATimeout() {
    userService.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(201).withFixedDelay(2000)));

    assertThrows(UserServiceTimeoutException.class, () -> client.create(REQUEST));
  }

  @Test
  void aServiceThatIsNotThereIsUnavailable() {
    String address = userService.baseUrl();
    userService.stop();

    UserServiceClient offline = clientFor(address, Duration.ofMillis(500));

    assertThrows(UserServiceUnavailableException.class, () -> offline.create(REQUEST));
  }

  @Test
  void deleteSendsTheKeyAndAcceptsNoContent() {
    userService.stubFor(delete(urlEqualTo("/internal/users/31"))
        .willReturn(aResponse().withStatus(204)));

    assertAll(
        () -> assertDoesNotThrow(() -> client.delete(31L)),
        () -> userService.verify(deleteRequestedFor(urlEqualTo("/internal/users/31"))
            .withHeader("X-Internal-Key", equalTo(KEY))));
  }

  /** A profile that is already gone makes the undoing safe to repeat. */
  @Test
  void deleteOfAProfileThatIsGoneIsNotAnError() {
    userService.stubFor(delete(urlEqualTo("/internal/users/31"))
        .willReturn(aResponse().withStatus(404)));

    assertDoesNotThrow(() -> client.delete(31L));
  }

  @Test
  void deleteWithAnErrorStatusIsUnavailable() {
    userService.stubFor(delete(urlEqualTo("/internal/users/31"))
        .willReturn(aResponse().withStatus(500)));

    assertThrows(UserServiceUnavailableException.class, () -> client.delete(31L));
  }

  @Test
  void deleteThatIsTooSlowIsATimeout() {
    userService.stubFor(delete(urlEqualTo("/internal/users/31"))
        .willReturn(aResponse().withStatus(204).withFixedDelay(2000)));

    assertThrows(UserServiceTimeoutException.class, () -> client.delete(31L));
  }

  /** A 401 means a wrong key: it must not be taken for "already gone". */
  @Test
  void deleteWithAWrongKeyIsUnavailable() {
    userService.stubFor(delete(urlEqualTo("/internal/users/31"))
        .willReturn(aResponse().withStatus(401)));

    assertThrows(UserServiceUnavailableException.class, () -> client.delete(31L));
  }
}
