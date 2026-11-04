package com.innowise.authservice.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.UserServiceTimeoutException;
import com.innowise.authservice.exception.UserServiceUnavailableException;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Tests the registration through the whole stack (servlet layer, service, PostgreSQL) with a
 * WireMock server in place of the User Service. The profile id (31) differs from the id of the
 * account (1), so mixing them up fails a test.
 */
class RegistrationIntegrationTest extends AbstractIntegrationTest {

  private static final String PASSWORD = "s3cret-passw0rd";
  private static final String BODY = """
      {"name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
       "email": "Alice@Example.com", "password": "s3cret-passw0rd"}
      """;

  @Autowired
  private PasswordEncoder passwordEncoder;

  private ResultActions register(String body) throws Exception {
    return mockMvc.perform(post("/api/auth/register")
        .contentType(MediaType.APPLICATION_JSON).content(body));
  }

  private static int deleteCalls() {
    return UserServiceStub.SERVER.findAll(
        deleteRequestedFor(urlEqualTo("/internal/users/31"))).size();
  }

  @Test
  void aRegisteredUserHasAProfileAndAnAccountWithTheRoleUser() throws Exception {
    UserServiceStub.createsProfile(31L, "alice@example.com");

    register(BODY).andExpectAll(
        status().isCreated(),
        jsonPath("$.id").value(31),
        jsonPath("$.email").value("alice@example.com"),
        jsonPath("$.password").doesNotExist());

    Map<String, Object> account = jdbcTemplate.queryForMap(
        "SELECT username, password_hash, role, user_id FROM credentials");
    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals("alice@example.com", account.get("username")),
        () -> assertEquals("USER", account.get("role")),
        () -> assertEquals(31L, account.get("user_id")),
        () -> assertTrue(passwordEncoder.matches(PASSWORD, (String) account.get("password_hash"))),
        () -> assertEquals(0, deleteCalls()));
  }

  @Test
  void theUserServiceReceivesTheProfileAndTheInternalKey() throws Exception {
    UserServiceStub.createsProfile(31L, "alice@example.com");

    register(BODY).andExpect(status().isCreated());

    UserServiceStub.SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/internal/users"))
        .withHeader("X-Internal-Key", equalTo("test-internal-key"))
        .withRequestBody(equalToJson("""
            {"name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
             "email": "Alice@Example.com"}
            """)));
  }

  /** The password of the request never goes to the User Service. */
  @Test
  void thePasswordIsNotSentToTheUserService() throws Exception {
    UserServiceStub.createsProfile(31L, "alice@example.com");

    register(BODY).andExpect(status().isCreated());

    List<LoggedRequest> sent = UserServiceStub.SERVER.findAll(
        postRequestedFor(urlEqualTo("/internal/users")));
    assertAll(
        () -> assertEquals(1, sent.size()),
        () -> assertFalse(sent.get(0).getBodyAsString().contains(PASSWORD)));
  }

  @Test
  void aRegisteredUserCanLogInAndTheTokenCarriesTheProfileId() throws Exception {
    UserServiceStub.createsProfile(31L, "alice@example.com");
    register(BODY).andExpect(status().isCreated());

    String login = mockMvc.perform(post("/api/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"login\": \"alice@example.com\", \"password\": \"s3cret-passw0rd\"}"))
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
    String token = JsonPath.read(login, "$.accessToken");

    mockMvc.perform(post("/api/auth/validate").contentType(MediaType.APPLICATION_JSON)
            .content(String.format("{\"token\": \"%s\"}", token)))
        .andExpectAll(
            status().isOk(),
            jsonPath("$.valid").value(true),
            jsonPath("$.userId").value(31),
            jsonPath("$.role").value("USER"));
  }

  @Test
  void aTakenEmailInTheUserServiceIs409WithNothingLeftBehind() throws Exception {
    UserServiceStub.createAnswers(409);

    register(BODY).andExpectAll(
        status().isConflict(),
        jsonPath("$.detail").value(EmailAlreadyRegisteredException.MESSAGE));

    assertAll(
        () -> assertEquals(0, countAccounts()),
        () -> assertEquals(0, deleteCalls()));
  }

  /** An account whose profile is gone holds the login: the new profile must be removed again. */
  @Test
  void aTakenLoginRemovesTheNewProfile() throws Exception {
    insertCredential("alice@example.com", "USER", 99L);
    UserServiceStub.createsProfile(31L, "alice@example.com");
    UserServiceStub.deleteAnswers(204);

    register(BODY).andExpectAll(
        status().isConflict(),
        jsonPath("$.detail").value(EmailAlreadyRegisteredException.MESSAGE));

    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals(1, deleteCalls()));
  }

  @Test
  void aFailedUndoingStillAnswers409() throws Exception {
    insertCredential("alice@example.com", "USER", 99L);
    UserServiceStub.createsProfile(31L, "alice@example.com");
    UserServiceStub.deleteAnswers(500);

    register(BODY).andExpect(status().isConflict());

    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals(1, deleteCalls()));
  }

  @Test
  void aUserServiceErrorIs502WithNothingLeftBehind() throws Exception {
    UserServiceStub.createAnswers(500);

    register(BODY).andExpectAll(
        status().isBadGateway(),
        jsonPath("$.detail").value(UserServiceUnavailableException.MESSAGE));

    assertAll(
        () -> assertEquals(0, countAccounts()),
        () -> assertEquals(0, deleteCalls()));
  }

  @Test
  void aSlowUserServiceIs504WithNothingLeftBehind() throws Exception {
    // Far above the read timeout of the shared context (5 s).
    UserServiceStub.createAnswersSlowly(7000);

    register(BODY).andExpectAll(
        status().isGatewayTimeout(),
        jsonPath("$.detail").value(UserServiceTimeoutException.MESSAGE));

    assertEquals(0, countAccounts());
  }

  /** The body is checked before any call: nothing reaches the User Service. */
  @Test
  void anInvalidBodyIs400AndTheUserServiceIsNotCalled() throws Exception {
    register("""
        {"name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
         "email": "alice@example.com", "password": "short"}
        """).andExpectAll(
            status().isBadRequest(),
            jsonPath("$.errors[0].field").value("password"));

    assertAll(
        () -> assertEquals(0, UserServiceStub.SERVER.getAllServeEvents().size()),
        () -> assertEquals(0, countAccounts()));
  }

  /**
   * Four registrations of the same email at once: the stub creates a profile for each, the
   * UNIQUE constraint lets one account in, and the three profiles of the losers are removed.
   */
  @RepeatedTest(3)
  void parallelRegistrationsOfOneEmailGiveOneAccountAndUndoTheOthers() throws Exception {
    UserServiceStub.createsProfile(31L, "alice@example.com");
    UserServiceStub.deleteAnswers(204);
    int threads = 4;
    CyclicBarrier barrier = new CyclicBarrier(threads);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      List<Future<Integer>> results = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        Callable<Integer> call = () -> {
          barrier.await();
          return register(BODY).andReturn().getResponse().getStatus();
        };
        results.add(pool.submit(call));
      }
      List<Integer> statuses = new ArrayList<>();
      for (Future<Integer> result : results) {
        statuses.add(result.get());
      }

      assertAll(
          () -> assertEquals(1, statuses.stream().filter(s -> s == 201).count()),
          () -> assertEquals(3, statuses.stream().filter(s -> s == 409).count()),
          () -> assertEquals(1, countAccounts()),
          () -> assertEquals(3, deleteCalls()));
    } finally {
      pool.shutdownNow();
    }
  }
}
