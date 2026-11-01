package com.innowise.authservice.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import com.github.tomakehurst.wiremock.WireMockServer;

/**
 * The User Service of the integration tests: one WireMock server on a free port, shared by every
 * test like the Spring context. Its address is given to the context as
 * {@code app.user-service.base-uri} by {@link AbstractIntegrationTest}.
 *
 * <p>Nothing is stubbed after {@link #reset()}, and WireMock answers 404 to a request it does not
 * know, so a test that forgets a stub fails visibly on {@code POST} (a 404 is an error for the
 * creation); on {@code DELETE} it is "already gone", so those calls are checked with
 * {@code verify}.
 */
final class UserServiceStub {

  /** The started server. */
  static final WireMockServer SERVER = start();

  private UserServiceStub() {
  }

  private static WireMockServer start() {
    WireMockServer server = new WireMockServer(options().dynamicPort());
    server.start();
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    return server;
  }

  /** Forgets every stub and every recorded request. */
  static void reset() {
    SERVER.resetAll();
  }

  /** The User Service creates the profile and answers with the stored (lowercase) email. */
  static void createsProfile(long id, String storedEmail) {
    SERVER.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(201)
        .withHeader("Content-Type", "application/json")
        .withBody(String.format("""
            {"id": %d, "name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
             "email": "%s", "active": true,
             "createdAt": "2026-10-31T10:00:00Z", "updatedAt": "2026-10-31T10:00:00Z"}
            """, id, storedEmail))));
  }

  /** The creation answers with this status and an empty body. */
  static void createAnswers(int status) {
    SERVER.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(status)));
  }

  /** The creation answers 201 after this many milliseconds. */
  static void createAnswersSlowly(int delayMillis) {
    SERVER.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(201).withFixedDelay(delayMillis)));
  }

  /** The deletion of any profile answers with this status. */
  static void deleteAnswers(int status) {
    SERVER.stubFor(delete(urlPathMatching("/internal/users/\\d+"))
        .willReturn(aResponse().withStatus(status)));
  }
}
