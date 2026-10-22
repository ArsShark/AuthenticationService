package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.exception.LoginAlreadyExistsException;
import com.grechanikovars.authenticationservice.exception.UserCredentialAlreadyExistsException;
import com.grechanikovars.authenticationservice.security.InternalKeyInterceptor;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.IntFunction;
import java.util.stream.IntStream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Tests the registration of accounts through HTTP, from the servlet layer to a real PostgreSQL.
 *
 * <p>The database is the real guard against duplicates, so the parallel tests send many requests
 * at once: a lost race must end as 409 (the UNIQUE constraint, recognized by its name), never as
 * 500.
 */
class CredentialRegistrationIntegrationTest extends AbstractIntegrationTest {

  private static final String PATH = "/internal/credentials";
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final int PARALLEL_REQUESTS = 8;

  @Value("${app.internal.api-key}")
  private String internalKey;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Test
  void registerStoresAnAccountWithABcryptHashOfThePassword() throws Exception {
    MvcResult result = register("Alice@Example.COM", PASSWORD, 7L).andExpectAll(
        status().isCreated(),
        jsonPath("$.login").value("alice@example.com"),
        jsonPath("$.role").value("USER"),
        jsonPath("$.userId").value(7),
        jsonPath("$.createdAt").value("2026-01-15T10:00:00Z"),
        jsonPath("$.passwordHash").doesNotExist()).andReturn();

    Map<String, Object> row = jdbcTemplate.queryForMap(
        "SELECT login, password_hash, role, user_id FROM credentials");
    String hash = (String) row.get("password_hash");
    String response = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    assertAll(
        () -> assertEquals("alice@example.com", row.get("login")),
        () -> assertEquals("USER", row.get("role")),
        () -> assertEquals(7L, ((Number) row.get("user_id")).longValue()),
        () -> assertEquals(60, hash.length()),
        () -> assertTrue(passwordEncoder.matches(PASSWORD, hash)),
        () -> assertFalse(response.contains(hash)),
        () -> assertFalse(response.contains(PASSWORD)));
  }

  @Test
  void samePasswordGivesDifferentHashesBecauseEverySaltIsUnique() throws Exception {
    register("alice@example.com", PASSWORD, 7L).andExpect(status().isCreated());
    register("bob@example.com", PASSWORD, 8L).andExpect(status().isCreated());

    List<String> hashes = jdbcTemplate.queryForList(
        "SELECT password_hash FROM credentials ORDER BY id", String.class);
    assertAll(
        () -> assertEquals(2, hashes.size()),
        () -> assertNotEquals(hashes.get(0), hashes.get(1)),
        () -> assertTrue(passwordEncoder.matches(PASSWORD, hashes.get(0))),
        () -> assertTrue(passwordEncoder.matches(PASSWORD, hashes.get(1))));
  }

  @Test
  void takenLoginIsConflictInAnyLetterCase() throws Exception {
    register("alice@example.com", PASSWORD, 7L).andExpect(status().isCreated());

    register("ALICE@example.com", "another-passw0rd", 8L).andExpectAll(
        status().isConflict(),
        jsonPath("$.detail").value(LoginAlreadyExistsException.MESSAGE));

    assertEquals(1, countAccounts());
  }

  @Test
  void userThatAlreadyHasAnAccountIsConflict() throws Exception {
    register("alice@example.com", PASSWORD, 7L).andExpect(status().isCreated());

    register("bob@example.com", PASSWORD, 7L).andExpectAll(
        status().isConflict(),
        jsonPath("$.detail").value(UserCredentialAlreadyExistsException.MESSAGE));

    assertEquals(1, countAccounts());
  }

  @Test
  void missingKeyIsUnauthorizedAndNothingIsWritten() throws Exception {
    mockMvc.perform(request("alice@example.com", PASSWORD, 7L))
        .andExpect(status().isUnauthorized());

    assertEquals(0, countAccounts());
  }

  @Test
  void wrongKeyIsUnauthorizedAndNothingIsWritten() throws Exception {
    mockMvc.perform(request("alice@example.com", PASSWORD, 7L)
        .header(InternalKeyInterceptor.HEADER, "wrong-key"))
        .andExpect(status().isUnauthorized());

    assertEquals(0, countAccounts());
  }

  @Test
  void invalidBodyIsBadRequestAndNothingIsWritten() throws Exception {
    register("not-an-email", PASSWORD, 7L).andExpectAll(
        status().isBadRequest(),
        jsonPath("$.errors[0].field").value("login"));

    assertEquals(0, countAccounts());
  }

  @RepeatedTest(5)
  void parallelRegistrationsOfOneLoginGiveOneCreatedAndTheRestConflict() throws Exception {
    List<Integer> statuses = registerInParallel(
        i -> request("alice@example.com", PASSWORD, 100L + i));

    assertAll(
        () -> assertEquals(1, Collections.frequency(statuses, 201)),
        () -> assertEquals(PARALLEL_REQUESTS - 1, Collections.frequency(statuses, 409)),
        () -> assertEquals(1, countAccounts()));
  }

  @RepeatedTest(5)
  void parallelRegistrationsOfOneUserGiveOneCreatedAndTheRestConflict() throws Exception {
    List<Integer> statuses = registerInParallel(
        i -> request(String.format("user%d@example.com", i), PASSWORD, 7L));

    assertAll(
        () -> assertEquals(1, Collections.frequency(statuses, 201)),
        () -> assertEquals(PARALLEL_REQUESTS - 1, Collections.frequency(statuses, 409)),
        () -> assertEquals(1, countAccounts()));
  }

  /** Sends a registration with the right internal key. */
  private ResultActions register(String login, String password, long userId) throws Exception {
    return mockMvc.perform(
        request(login, password, userId).header(InternalKeyInterceptor.HEADER, internalKey));
  }

  /** Builds a registration request without the internal key. */
  private static MockHttpServletRequestBuilder request(String login, String password,
      long userId) {
    String body = """
        {"login": "%s", "password": "%s", "userId": %d}
        """.formatted(login, password, userId);
    return post(PATH).contentType(MediaType.APPLICATION_JSON).content(body);
  }

  /**
   * Sends {@value #PARALLEL_REQUESTS} requests at the same moment (a barrier releases all threads
   * together) and returns their statuses.
   *
   * @param requestFor builds the request of the thread with the given index
   */
  private List<Integer> registerInParallel(IntFunction<MockHttpServletRequestBuilder> requestFor)
      throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(PARALLEL_REQUESTS);
    CyclicBarrier barrier = new CyclicBarrier(PARALLEL_REQUESTS);
    try {
      List<Callable<Integer>> tasks = IntStream.range(0, PARALLEL_REQUESTS)
          .<Callable<Integer>>mapToObj(i -> () -> {
            MockHttpServletRequestBuilder request =
                requestFor.apply(i).header(InternalKeyInterceptor.HEADER, internalKey);
            barrier.await();
            return mockMvc.perform(request).andReturn().getResponse().getStatus();
          })
          .toList();
      List<Integer> statuses = new ArrayList<>();
      for (Future<Integer> future : executor.invokeAll(tasks)) {
        statuses.add(future.get());
      }
      return statuses;
    } finally {
      executor.shutdownNow();
    }
  }

  private int countAccounts() {
    return Objects.requireNonNull(
        jdbcTemplate.queryForObject("SELECT count(*) FROM credentials", Integer.class));
  }
}
