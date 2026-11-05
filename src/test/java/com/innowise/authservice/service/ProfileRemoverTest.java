package com.innowise.authservice.service;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.exception.UserServiceTimeoutException;
import com.innowise.authservice.exception.UserServiceUnavailableException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests the bounded retry of the deletion. The pause is a recording lambda, so no test waits.
 */
@ExtendWith(MockitoExtension.class)
class ProfileRemoverTest {

  private static final UUID ID = UUID.fromString("0b9c4b5e-6f3e-4a56-9d3a-5f6f0d2a7c11");

  @Mock
  private UserServiceClient users;

  private final List<Duration> pauses = new ArrayList<>();

  private ProfileRemover remover() {
    return new ProfileRemover(users, pauses::add);
  }

  @Test
  void aDeletionThatWorksIsNotRepeatedAndNeverWaits() {
    boolean removed = remover().remove(ID);

    assertAll(
        () -> assertTrue(removed),
        () -> verify(users).deleteByRegistrationId(ID),
        () -> assertEquals(List.of(), pauses));
  }

  @Test
  void aDeletionThatFailsOnceIsRepeatedAfterTheFirstPause() {
    doThrow(new UserServiceUnavailableException(true))
        .doNothing()
        .when(users).deleteByRegistrationId(ID);

    boolean removed = remover().remove(ID);

    assertAll(
        () -> assertTrue(removed),
        () -> verify(users, times(2)).deleteByRegistrationId(ID),
        () -> assertEquals(List.of(Duration.ofMillis(200)), pauses));
  }

  @Test
  void aDeletionThatFailsTwiceSucceedsAtTheThirdAttempt() {
    doThrow(new UserServiceTimeoutException(true))
        .doThrow(new UserServiceUnavailableException(true))
        .doNothing()
        .when(users).deleteByRegistrationId(ID);

    boolean removed = remover().remove(ID);

    assertAll(
        () -> assertTrue(removed),
        () -> verify(users, times(3)).deleteByRegistrationId(ID),
        () -> assertEquals(List.of(Duration.ofMillis(200), Duration.ofMillis(400)), pauses));
  }

  /** Three attempts in all, two pauses, none after the last: then it gives up without throwing. */
  @Test
  void aDeletionThatAlwaysFailsGivesUpAfterThreeAttempts() {
    doThrow(new UserServiceTimeoutException(true)).when(users).deleteByRegistrationId(ID);

    boolean removed = remover().remove(ID);

    assertAll(
        () -> assertFalse(removed),
        () -> verify(users, times(ProfileRemover.ATTEMPTS)).deleteByRegistrationId(ID),
        () -> assertEquals(List.of(Duration.ofMillis(200), Duration.ofMillis(400)), pauses));
  }

  /** The client wraps its failures, but a bug must not escape and hide the original error. */
  @Test
  void anUnexpectedErrorIsRepeatedAndNeverThrown() {
    doThrow(new IllegalStateException("bug"))
        .doNothing()
        .when(users).deleteByRegistrationId(ID);

    assertTrue(remover().remove(ID));
  }

  @Test
  void everyAttemptUsesTheSameRegistrationId() {
    doThrow(new UserServiceUnavailableException(true)).when(users).deleteByRegistrationId(ID);

    remover().remove(ID);

    verify(users, times(3)).deleteByRegistrationId(ID);
  }

  @Test
  void aThreadThatIsInterruptedWhileWaitingStopsAndKeepsTheFlag() {
    doThrow(new UserServiceUnavailableException(true)).when(users).deleteByRegistrationId(ID);
    ProfileRemover interrupted = new ProfileRemover(users, duration -> {
      throw new InterruptedException();
    });

    boolean removed = interrupted.remove(ID);
    boolean flag = Thread.interrupted();

    assertAll(
        () -> assertFalse(removed),
        () -> assertTrue(flag, "the interrupt flag is restored"),
        () -> verify(users).deleteByRegistrationId(ID));
  }

  @Test
  void theRealPauseReturnsAfterTheGivenTime() {
    assertDoesNotThrow(() -> new ThreadPause().sleep(Duration.ofMillis(1)));
  }
}
