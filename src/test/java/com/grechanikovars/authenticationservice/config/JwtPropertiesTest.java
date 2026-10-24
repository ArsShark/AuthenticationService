package com.grechanikovars.authenticationservice.config;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/**
 * Checks the binding of the {@code app.jwt} settings and the rules that stop the startup.
 */
class JwtPropertiesTest {

  private static final Duration ACCESS = Duration.ofMinutes(15);
  private static final Duration REFRESH = Duration.ofDays(7);

  @Test
  void bindsTheSettingsFromIsoDurationsAndKebabCaseNames() {
    JwtProperties bound = bind(Map.of(
        "app.jwt.private-key", "the-key",
        "app.jwt.access-ttl", "PT15M",
        "app.jwt.refresh-ttl", "P7D",
        "app.jwt.issuer", "authentication-service"));

    assertAll(
        () -> assertEquals("the-key", bound.privateKey()),
        () -> assertEquals(ACCESS, bound.accessTtl()),
        () -> assertEquals(REFRESH, bound.refreshTtl()),
        () -> assertEquals("authentication-service", bound.issuer()));
  }

  /** A wrong value must stop the startup, so the rules also apply when Spring binds them. */
  @Test
  void aWrongValueFailsTheBinding() {
    Map<String, String> wrong = Map.of(
        "app.jwt.private-key", "the-key",
        "app.jwt.access-ttl", "PT15M",
        "app.jwt.refresh-ttl", "PT1M",
        "app.jwt.issuer", "authentication-service");

    assertThrows(BindException.class, () -> bind(wrong));
  }

  @ParameterizedTest
  @ValueSource(strings = {"PT0S", "-PT1M"})
  void rejectsAnAccessLifetimeThatIsNotPositive(String text) {
    IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
        () -> new JwtProperties("k", Duration.parse(text), REFRESH, "issuer"));

    assertTrue(error.getMessage().contains("app.jwt.access-ttl"), error.getMessage());
  }

  @ParameterizedTest
  @ValueSource(strings = {"PT0S", "-P1D"})
  void rejectsARefreshLifetimeThatIsNotPositive(String text) {
    IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
        () -> new JwtProperties("k", ACCESS, Duration.parse(text), "issuer"));

    assertTrue(error.getMessage().contains("app.jwt.refresh-ttl"), error.getMessage());
  }

  @Test
  void rejectsMissingLifetimes() {
    assertAll(
        () -> assertThrows(IllegalArgumentException.class,
            () -> new JwtProperties("k", null, REFRESH, "issuer")),
        () -> assertThrows(IllegalArgumentException.class,
            () -> new JwtProperties("k", ACCESS, null, "issuer")));
  }

  @Test
  void refreshTokenMustLiveLongerThanTheAccessToken() {
    assertAll(
        () -> assertThrows(IllegalArgumentException.class,
            () -> new JwtProperties("k", ACCESS, ACCESS, "issuer")),
        () -> assertThrows(IllegalArgumentException.class,
            () -> new JwtProperties("k", ACCESS, Duration.ofMinutes(1), "issuer")));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void rejectsABlankIssuer(String issuer) {
    IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
        () -> new JwtProperties("k", ACCESS, REFRESH, issuer));

    assertTrue(error.getMessage().contains("app.jwt.issuer"), error.getMessage());
  }

  /** The key is not checked here, so the error that mentions a property never holds the key. */
  @Test
  void doesNotCheckTheKey() {
    assertAll(
        () -> new JwtProperties(null, ACCESS, REFRESH, "issuer"),
        () -> new JwtProperties("", ACCESS, REFRESH, "issuer"));
  }

  @Test
  void toStringDoesNotPrintTheKey() {
    String text = new JwtProperties("secret-key-123", ACCESS, REFRESH, "issuer").toString();

    assertAll(
        () -> assertFalse(text.contains("secret-key-123")),
        () -> assertTrue(text.startsWith("JwtProperties")),
        () -> assertTrue(text.contains("issuer=issuer")));
  }

  private static JwtProperties bind(Map<String, String> properties) {
    return new Binder(new MapConfigurationPropertySource(properties))
        .bind("app.jwt", JwtProperties.class)
        .get();
  }
}
