package com.innowise.authservice.service;

import com.innowise.authservice.client.UserServiceClient;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Removes the profile of a failed registration, and tries again when the call fails.
 *
 * <p>The deletion by registration id is idempotent (a profile that is already gone is a 404 that
 * the client accepts), so repeating it is safe. There are {@value #ATTEMPTS} attempts in all, with
 * the pauses of {@link #PAUSES} between them (none after the last). A deletion can fail because
 * the User Service is briefly unavailable, which is the usual reason a registration failed in the
 * first place, so a short wait often helps; a long one would keep the request, a servlet thread
 * and the caller waiting. The worst case is about three read timeouts of the client plus the
 * pauses.
 *
 * <p>When every attempt fails the profile stays, and the registration id in the ERROR line is
 * what an operator needs to remove it ({@code DELETE /internal/users/by-registration/{id}}).
 * {@link #remove} never throws: the caller has an error of its own to report, and a failed
 * deletion must not hide it.
 */
@Component
public class ProfileRemover {

  /** The number of attempts: the first one and two repeats. */
  static final int ATTEMPTS = 3;

  /** The pause before the second and before the third attempt. */
  static final List<Duration> PAUSES = List.of(Duration.ofMillis(200), Duration.ofMillis(400));

  private static final Logger LOGGER = LoggerFactory.getLogger(ProfileRemover.class);

  private final UserServiceClient users;
  private final Pause pause;

  public ProfileRemover(UserServiceClient users, Pause pause) {
    this.users = users;
    this.pause = pause;
  }

  /**
   * Removes the profile that was created with this registration id.
   *
   * @param registrationId the id sent with the creation
   * @return {@code true} if the User Service confirmed that the profile is gone (or never
   *     existed), {@code false} if every attempt failed or the thread was interrupted
   */
  public boolean remove(UUID registrationId) {
    int attempt = 0;
    while (attempt < ATTEMPTS) {
      attempt++;
      try {
        users.deleteByRegistrationId(registrationId);
        return true;
      } catch (RuntimeException e) {
        LOGGER.warn("Attempt {} of {} to remove the profile of registration {} failed ({})",
            attempt, ATTEMPTS, registrationId, e.getClass().getSimpleName());
      }
      if (attempt < ATTEMPTS && !waitBefore(attempt + 1)) {
        break;
      }
    }
    LOGGER.error("Undoing registration {} is incomplete after {} attempts: remove its profile",
        registrationId, attempt);
    return false;
  }

  /** Waits before the given attempt; {@code false} if the thread was interrupted. */
  private boolean waitBefore(int nextAttempt) {
    try {
      pause.sleep(PAUSES.get(nextAttempt - 2));
      return true;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }
}
