package com.innowise.authservice.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import java.util.List;

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

  /** The path pattern of the deletion of a profile by its registration id. */
  static final String BY_REGISTRATION_PATTERN = String.format(
      "/internal/users/by-registration/%s",
      "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

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

  /** The creation answers with this status and this JSON body. */
  static void createAnswers(int status, String jsonBody) {
    SERVER.stubFor(post(urlEqualTo("/internal/users")).willReturn(aResponse()
        .withStatus(status)
        .withHeader("Content-Type", "application/json")
        .withBody(jsonBody)));
  }

  /**
   * The answer of the creation is lost: the connection breaks as soon as the request is read.
   * The test does not wait for a timeout.
   */
  static void createLosesTheAnswer() {
    SERVER.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
  }

  /** The creation answers 201 after this many milliseconds. */
  static void createAnswersSlowly(int delayMillis) {
    SERVER.stubFor(post(urlEqualTo("/internal/users"))
        .willReturn(aResponse().withStatus(201).withFixedDelay(delayMillis)));
  }

  /** The deletion of any profile by registration id answers with this status. */
  static void deleteAnswers(int status) {
    SERVER.stubFor(delete(urlPathMatching(BY_REGISTRATION_PATTERN))
        .willReturn(aResponse().withStatus(status)));
  }

  /**
   * The deletions answer with these statuses one after the other, and the last status repeats.
   * It is a WireMock scenario, so the order is exact and no test has to wait.
   */
  static void deleteAnswersInOrder(int... statuses) {
    String state = Scenario.STARTED;
    for (int i = 0; i < statuses.length; i++) {
      boolean last = i == statuses.length - 1;
      String next = last ? state : String.format("deletion-%d", i + 1);
      SERVER.stubFor(delete(urlPathMatching(BY_REGISTRATION_PATTERN))
          .inScenario("deletion")
          .whenScenarioStateIs(state)
          .willSetStateTo(next)
          .willReturn(aResponse().withStatus(statuses[i])));
      state = next;
    }
  }

  /** The creations of profiles received so far, oldest first. */
  static List<LoggedRequest> creations() {
    return SERVER.findAll(postRequestedFor(urlEqualTo("/internal/users")));
  }

  /** The deletions of profiles by registration id received so far, oldest first. */
  static List<LoggedRequest> deletions() {
    return SERVER.findAll(deleteRequestedFor(urlPathMatching(BY_REGISTRATION_PATTERN)));
  }
}
