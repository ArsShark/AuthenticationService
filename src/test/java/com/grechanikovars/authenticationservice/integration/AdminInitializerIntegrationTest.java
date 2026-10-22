package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.grechanikovars.authenticationservice.config.AdminInitializer;
import com.grechanikovars.authenticationservice.config.AdminProperties;
import com.grechanikovars.authenticationservice.service.CredentialService;
import jakarta.validation.Validator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Tests the creation of the first admin against a real PostgreSQL.
 *
 * <p>The shared context has the admin switched off (one context for all tests), so the tests run
 * an {@link AdminInitializer} that they build themselves, with the real service and validator.
 */
class AdminInitializerIntegrationTest extends AbstractIntegrationTest {

  private static final String LOGIN = "admin@example.com";
  private static final String PASSWORD = "Adm1n-passw0rd";
  private static final int INSTANCES = 8;

  @Autowired
  private CredentialService credentialService;

  @Autowired
  private Validator validator;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Test
  void createsAnAdminWithoutAProfile() {
    runInitializer("Admin@Example.COM", PASSWORD);

    Map<String, Object> row = jdbcTemplate.queryForMap(
        "SELECT login, password_hash, role, user_id FROM credentials");
    String hash = (String) row.get("password_hash");
    assertAll(
        () -> assertEquals(LOGIN, row.get("login")),
        () -> assertEquals("ADMIN", row.get("role")),
        () -> assertNull(row.get("user_id")),
        () -> assertEquals(60, hash.length()),
        () -> assertTrue(passwordEncoder.matches(PASSWORD, hash)));
  }

  @Test
  void aSecondStartKeepsThePasswordOfTheFirstOne() {
    runInitializer(LOGIN, PASSWORD);
    String firstHash = passwordHash();

    runInitializer(LOGIN, "Another-passw0rd");

    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals(firstHash, passwordHash()),
        () -> assertTrue(passwordEncoder.matches(PASSWORD, passwordHash())));
  }

  @Test
  void theLoginOfAUserIsNotTakenOver() {
    insertCredential(LOGIN, "USER", 7L);

    runInitializer(LOGIN, PASSWORD);

    Map<String, Object> row = jdbcTemplate.queryForMap(
        "SELECT role, password_hash FROM credentials");
    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals("USER", row.get("role")),
        () -> assertEquals(HASH, row.get("password_hash")));
  }

  /** Several instances of the service start at the same moment: one admin, no failed start. */
  @RepeatedTest(5)
  void parallelStartsCreateExactlyOneAdminAndNoneFails() throws Exception {
    CyclicBarrier barrier = new CyclicBarrier(INSTANCES);
    ExecutorService executor = Executors.newFixedThreadPool(INSTANCES);
    try {
      List<Callable<Void>> starts = IntStream.range(0, INSTANCES)
          .<Callable<Void>>mapToObj(i -> () -> {
            barrier.await();
            runInitializer(LOGIN, PASSWORD);
            return null;
          })
          .toList();
      for (Future<Void> start : executor.invokeAll(starts)) {
        start.get();
      }
    } finally {
      executor.shutdownNow();
    }

    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals("ADMIN", jdbcTemplate.queryForObject(
            "SELECT role FROM credentials", String.class)));
  }

  private void runInitializer(String login, String password) {
    new AdminInitializer(new AdminProperties(login, password), credentialService, validator)
        .run(new DefaultApplicationArguments());
  }

  private String passwordHash() {
    return jdbcTemplate.queryForObject("SELECT password_hash FROM credentials", String.class);
  }
}
