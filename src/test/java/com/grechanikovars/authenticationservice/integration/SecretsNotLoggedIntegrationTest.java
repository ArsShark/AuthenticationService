package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.TestKeys;
import com.grechanikovars.authenticationservice.service.CredentialService;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Proves the rule that no password, hash, token, login, {@code jti}, key or internal key ever
 * reaches the log, for the whole service at once.
 *
 * <p>An appender is attached to the logger that serves the whole application, then one run goes
 * through every endpoint, with successes and with every kind of failure. Afterwards each secret
 * that the run produced is searched for in everything that was logged, from any library.
 *
 * <p>The test checks itself: it also requires lines that the run must have written, so a
 * capture that sees nothing fails instead of passing for nothing.
 */
class SecretsNotLoggedIntegrationTest extends AbstractIntegrationTest {

  private static final String INTERNAL_KEY = "test-internal-key";
  private static final String WRONG_INTERNAL_KEY = "wrong-internal-key";
  private static final String LOGIN = "alice@example.com";
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final String WRONG_PASSWORD = "wr0ng-passw0rd";
  private static final String LONG_PASSWORD = "L".repeat(73);
  private static final String UNKNOWN_LOGIN = "nobody@example.com";
  private static final String ADMIN_LOGIN = "admin@example.com";
  private static final String ADMIN_PASSWORD = "Adm1n-passw0rd";
  private static final String CAROL_LOGIN = "carol@example.com";
  private static final String CAROL_PASSWORD = "c4rol-passw0rd";

  @Autowired
  private CredentialService credentialService;

  @Test
  void noSecretOfAnyKindReachesTheLog() throws Exception {
    CapturingAppender appender = CapturingAppender.attach();
    String firstAccess;
    String firstRefresh;
    String secondAccess;
    String secondRefresh;
    try {
      credentialService.register(LOGIN, PASSWORD, 7L);
      credentialService.createAdminIfAbsent(ADMIN_LOGIN, ADMIN_PASSWORD);

      String first = bodyOf(login(LOGIN, PASSWORD).andExpect(status().isOk()));
      firstAccess = JsonPath.read(first, "$.accessToken");
      firstRefresh = JsonPath.read(first, "$.refreshToken");
      login(LOGIN, WRONG_PASSWORD).andExpect(status().isUnauthorized());
      login(UNKNOWN_LOGIN, PASSWORD).andExpect(status().isUnauthorized());
      login(LOGIN, LONG_PASSWORD).andExpect(status().isUnauthorized());
      login("", PASSWORD).andExpect(status().isBadRequest());

      send("/api/auth/validate", String.format("{\"token\": \"%s\"}", firstAccess))
          .andExpect(status().isOk());
      send("/api/auth/validate", "{\"token\": \"not-a-token\"}").andExpect(status().isOk());

      String second = bodyOf(send("/api/auth/refresh",
          String.format("{\"refreshToken\": \"%s\"}", firstRefresh)).andExpect(status().isOk()));
      secondAccess = JsonPath.read(second, "$.accessToken");
      secondRefresh = JsonPath.read(second, "$.refreshToken");
      // The used token again: a reuse, which logs a warning and revokes the whole account.
      send("/api/auth/refresh", String.format("{\"refreshToken\": \"%s\"}", firstRefresh))
          .andExpect(status().isUnauthorized());
      send("/api/auth/refresh", "{\"refreshToken\": \"not-a-token\"}")
          .andExpect(status().isUnauthorized());

      String carol = String.format("{\"login\": \"%s\", \"password\": \"%s\", \"userId\": 9}",
          CAROL_LOGIN, CAROL_PASSWORD);
      internal(carol, INTERNAL_KEY).andExpect(status().isCreated());
      internal(carol, INTERNAL_KEY).andExpect(status().isConflict());
      internal(carol, WRONG_INTERNAL_KEY).andExpect(status().isUnauthorized());
    } finally {
      appender.detach();
    }

    List<String> lines = appender.lines();
    Map<String, String> secrets = secretsOfTheRun(
        firstAccess, firstRefresh, secondAccess, secondRefresh);
    List<String> leaked = secrets.entrySet().stream()
        .filter(secret -> lines.stream().anyMatch(line -> line.contains(secret.getValue())))
        .map(Map.Entry::getKey)
        .toList();
    assertAll(
        () -> assertTrue(containsLine(lines, "logged in"), "the capture sees the login"),
        () -> assertTrue(containsLine(lines, "refreshed its tokens"), "and the refresh"),
        () -> assertTrue(containsLine(lines, "valid tokens revoked"), "and the reuse warning"),
        () -> assertEquals(List.of(), leaked, "secrets found in the log"));
  }

  /** Every secret that the run produced or used, by a label that names it in a failure. */
  private Map<String, String> secretsOfTheRun(String firstAccess, String firstRefresh,
      String secondAccess, String secondRefresh) {
    Map<String, String> secrets = new LinkedHashMap<>();
    secrets.put("password", PASSWORD);
    secrets.put("wrong password", WRONG_PASSWORD);
    secrets.put("too long password", LONG_PASSWORD);
    secrets.put("admin password", ADMIN_PASSWORD);
    secrets.put("carol password", CAROL_PASSWORD);
    secrets.put("login", LOGIN);
    secrets.put("unknown login", UNKNOWN_LOGIN);
    secrets.put("admin login", ADMIN_LOGIN);
    secrets.put("carol login", CAROL_LOGIN);
    secrets.put("first access token", firstAccess);
    secrets.put("first refresh token", firstRefresh);
    secrets.put("second access token", secondAccess);
    secrets.put("second refresh token", secondRefresh);
    secrets.put("internal key", INTERNAL_KEY);
    secrets.put("wrong internal key", WRONG_INTERNAL_KEY);
    secrets.put("private key", TestKeys.PRIVATE_KEY_BASE64);
    secrets.put("part of the private key", TestKeys.PRIVATE_KEY_BASE64.substring(100, 160));
    List<String> jtis =
        jdbcTemplate.queryForList("SELECT jti::text FROM refresh_tokens", String.class);
    for (int i = 0; i < jtis.size(); i++) {
      secrets.put(String.format("jti %d", i), jtis.get(i));
    }
    List<String> hashes =
        jdbcTemplate.queryForList("SELECT password_hash FROM credentials", String.class);
    for (int i = 0; i < hashes.size(); i++) {
      secrets.put(String.format("password hash %d", i), hashes.get(i));
    }
    return secrets;
  }

  private static boolean containsLine(List<String> lines, String text) {
    return lines.stream().anyMatch(line -> line.contains(text));
  }

  private ResultActions login(String login, String password) throws Exception {
    String body = String.format("{\"login\": \"%s\", \"password\": \"%s\"}", login, password);
    return send("/api/auth/login", body);
  }

  private ResultActions internal(String body, String key) throws Exception {
    return mockMvc.perform(post("/internal/credentials")
        .header("X-Internal-Key", key)
        .contentType(MediaType.APPLICATION_JSON).content(body));
  }

  private ResultActions send(String path, String body) throws Exception {
    return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  private static String bodyOf(ResultActions actions) throws Exception {
    MvcResult result = actions.andReturn();
    return result.getResponse().getContentAsString(StandardCharsets.UTF_8);
  }

  /**
   * Collects the text of every log event: the message and the exception, if there is one. It is
   * attached to the logger configuration that serves the application, which here is the root
   * one, so it sees the events of every library too.
   */
  private static final class CapturingAppender extends AbstractAppender {

    private static final String NAME = "secrets-test-capture";

    private final List<String> lines = new CopyOnWriteArrayList<>();
    private final LoggerContext context;
    private final LoggerConfig target;

    private CapturingAppender(LoggerContext context, LoggerConfig target) {
      super(NAME, null, null, true, Property.EMPTY_ARRAY);
      this.context = context;
      this.target = target;
    }

    static CapturingAppender attach() {
      LoggerContext context = (LoggerContext) LogManager.getContext(false);
      LoggerConfig target = context.getConfiguration()
          .getLoggerConfig("com.grechanikovars.authenticationservice");
      CapturingAppender appender = new CapturingAppender(context, target);
      appender.start();
      target.addAppender(appender, Level.ALL, null);
      context.updateLoggers();
      return appender;
    }

    void detach() {
      target.removeAppender(NAME);
      context.updateLoggers();
      stop();
    }

    List<String> lines() {
      return List.copyOf(lines);
    }

    @Override
    public void append(LogEvent event) {
      Throwable thrown = event.getThrown();
      lines.add(String.format("%s %s", event.getMessage().getFormattedMessage(),
          thrown == null ? "" : thrown));
    }
  }
}
