package com.innowise.authservice.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
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
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    return UserServiceStub.deletions().size();
  }

  /**
   * The distinct registration ids of the requests: the header of a creation, the last path
   * segment of a deletion.
   */
  private static Set<String> registrationIdsOf(List<LoggedRequest> requests) {
    Set<String> ids = new HashSet<>();
    for (LoggedRequest request : requests) {
      String header = request.getHeader("X-Registration-Id");
      ids.add(header != null ? header : request.getUrl().substring(
          request.getUrl().lastIndexOf('/') + 1));
    }
    return ids;
  }

  /** The registration id of the one deletion of the test (the last path segment). */
  private static String deletedRegistrationId() {
    List<LoggedRequest> deletions = UserServiceStub.deletions();
    assertEquals(1, deletions.size());
    String url = deletions.get(0).getUrl();
    return url.substring(url.lastIndexOf('/') + 1);
  }

  /** The registration id of the one creation of the test, as the User Service received it. */
  private static String sentRegistrationId() {
    List<LoggedRequest> creations = UserServiceStub.creations();
    assertEquals(1, creations.size());
    return creations.get(0).getHeader("X-Registration-Id");
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
        .withHeader("X-Registration-Id", matching("[0-9a-f-]{36}"))
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
        () -> assertEquals(1, deleteCalls()),
        () -> assertEquals(
            String.format("/internal/users/by-registration/%s", sentRegistrationId()),
            UserServiceStub.deletions().get(0).getUrl()),
        () -> assertEquals("test-internal-key",
            UserServiceStub.deletions().get(0).getHeader("X-Internal-Key")));
  }

  /** The undoing is tried three times, with the two pauses, and then given up: still a 409. */
  @Test
  void anUndoingThatKeepsFailingIsGivenUpAfterThreeAttemptsAndStillAnswers409()
      throws Exception {
    insertCredential("alice@example.com", "USER", 99L);
    UserServiceStub.createsProfile(31L, "alice@example.com");
    UserServiceStub.deleteAnswers(500);

    register(BODY).andExpect(status().isConflict());

    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals(3, deleteCalls()),
        () -> assertEquals(1, registrationIdsOf(UserServiceStub.deletions()).size()),
        () -> assertEquals(List.of(Duration.ofMillis(200), Duration.ofMillis(400)),
            pause.pauses()));
  }

  /** A deletion that fails once and then works: the profile is removed, the caller sees a 409. */
  @Test
  void aFailedUndoingIsRepeatedAndWorks() throws Exception {
    insertCredential("alice@example.com", "USER", 99L);
    UserServiceStub.createsProfile(31L, "alice@example.com");
    UserServiceStub.deleteAnswersInOrder(500, 204);

    register(BODY).andExpect(status().isConflict());

    assertAll(
        () -> assertEquals(2, deleteCalls()),
        () -> assertEquals(1, registrationIdsOf(UserServiceStub.deletions()).size()),
        () -> assertEquals(List.of(Duration.ofMillis(200)), pause.pauses()));
  }

  /** A lost answer and a User Service that is still down for the first two deletions. */
  @Test
  void aLostAnswerIsUndoneAfterTwoFailedDeletions() throws Exception {
    UserServiceStub.createLosesTheAnswer();
    UserServiceStub.deleteAnswersInOrder(503, 500, 204);

    register(BODY).andExpect(status().isBadGateway());

    assertAll(
        () -> assertEquals(0, countAccounts()),
        () -> assertEquals(3, deleteCalls()),
        () -> assertEquals(1, registrationIdsOf(UserServiceStub.deletions()).size()),
        () -> assertEquals(sentRegistrationId(),
            registrationIdsOf(UserServiceStub.deletions()).iterator().next()),
        () -> assertEquals(List.of(Duration.ofMillis(200), Duration.ofMillis(400)),
            pause.pauses()));
  }

  /** A deletion that works at once never pauses. */
  @Test
  void aDeletionThatWorksNeverPauses() throws Exception {
    UserServiceStub.createLosesTheAnswer();
    UserServiceStub.deleteAnswers(204);

    register(BODY).andExpect(status().isBadGateway());

    assertEquals(List.of(), pause.pauses());
  }

  /** A 5xx may come after the profile was created: the profile of this attempt is removed. */
  @Test
  void aUserServiceErrorIs502AndTheProfileThatMayExistIsUndone() throws Exception {
    UserServiceStub.createAnswers(500);
    UserServiceStub.deleteAnswers(204);

    register(BODY).andExpectAll(
        status().isBadGateway(),
        jsonPath("$.detail").value(UserServiceUnavailableException.MESSAGE));

    assertAll(
        () -> assertEquals(0, countAccounts()),
        () -> assertEquals(1, deleteCalls()),
        () -> assertEquals(sentRegistrationId(), deletedRegistrationId()));
  }

  /** The User Service rejects the request (4xx) before it changes anything: no deletion. */
  @Test
  void aRejectedCreationIs502AndIsNotUndone() throws Exception {
    UserServiceStub.createAnswers(400);
    UserServiceStub.deleteAnswers(204);

    register(BODY).andExpectAll(
        status().isBadGateway(),
        jsonPath("$.detail").value(UserServiceUnavailableException.MESSAGE));

    assertAll(
        () -> assertEquals(0, countAccounts()),
        () -> assertEquals(0, deleteCalls()));
  }

  /** The reported case: the profile exists, the answer is lost; the email must not stay taken. */
  @Test
  void aLostAnswerIs502AndTheProfileThatMayExistIsUndone() throws Exception {
    UserServiceStub.createLosesTheAnswer();
    UserServiceStub.deleteAnswers(204);

    register(BODY).andExpectAll(
        status().isBadGateway(),
        jsonPath("$.detail").value(UserServiceUnavailableException.MESSAGE));

    assertAll(
        () -> assertEquals(0, countAccounts()),
        () -> assertEquals(1, UserServiceStub.creations().size()),
        () -> assertEquals(1, deleteCalls()),
        () -> assertEquals(sentRegistrationId(), deletedRegistrationId()));
  }

  /** A 201 without an id means the profile exists but cannot be named: undo it by the id. */
  @Test
  void aCreatedAnswerWithoutAnIdIs502AndTheProfileIsUndone() throws Exception {
    UserServiceStub.createAnswers(201, "{\"email\": \"alice@example.com\"}");
    UserServiceStub.deleteAnswers(204);

    register(BODY).andExpect(status().isBadGateway());

    assertAll(
        () -> assertEquals(0, countAccounts()),
        () -> assertEquals(1, deleteCalls()),
        () -> assertEquals(sentRegistrationId(), deletedRegistrationId()));
  }

  /** After a lost answer was undone, the user can register again (the email is not taken). */
  @Test
  void aRetryAfterALostAnswerSucceeds() throws Exception {
    UserServiceStub.createLosesTheAnswer();
    UserServiceStub.deleteAnswers(204);
    register(BODY).andExpect(status().isBadGateway());

    UserServiceStub.createsProfile(31L, "alice@example.com");
    register(BODY).andExpectAll(status().isCreated(), jsonPath("$.id").value(31));

    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals(1, deleteCalls()),
        // Two attempts, two different registration ids.
        () -> assertEquals(2, registrationIdsOf(UserServiceStub.creations()).size()));
  }

  /** A timeout of the answer: the profile may exist, so it is undone as well. */
  @Test
  void aSlowUserServiceIs504AndTheProfileThatMayExistIsUndone() throws Exception {
    // Far above the read timeout of the shared context (5 s).
    UserServiceStub.createAnswersSlowly(7000);
    UserServiceStub.deleteAnswers(204);

    register(BODY).andExpectAll(
        status().isGatewayTimeout(),
        jsonPath("$.detail").value(UserServiceTimeoutException.MESSAGE));

    assertAll(
        () -> assertEquals(0, countAccounts()),
        () -> assertEquals(1, deleteCalls()),
        () -> assertEquals(sentRegistrationId(), deletedRegistrationId()));
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
          () -> assertEquals(3, deleteCalls()),
          // Four attempts with four ids; each loser removes only its own profile.
          () -> assertEquals(4, registrationIdsOf(UserServiceStub.creations()).size()),
          () -> assertEquals(3, registrationIdsOf(UserServiceStub.deletions()).size()),
          () -> assertTrue(registrationIdsOf(UserServiceStub.creations())
              .containsAll(registrationIdsOf(UserServiceStub.deletions()))));
    } finally {
      pool.shutdownNow();
    }
  }
}
