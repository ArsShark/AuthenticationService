package com.grechanikovars.authenticationservice.repository;

import com.grechanikovars.authenticationservice.entity.Credential;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Stores and loads {@link Credential} rows.
 *
 * <p>Logins are stored in lowercase and the service normalizes them before every call, so the
 * derived queries here compare plain strings.
 */
public interface CredentialRepository extends JpaRepository<Credential, Long> {

  /**
   * Finds the account with this login.
   *
   * @param login the normalized (stripped, lowercase) login
   */
  Optional<Credential> findByLogin(String login);

  /**
   * Tells whether an account with this login exists.
   *
   * @param login the normalized (stripped, lowercase) login
   */
  boolean existsByLogin(String login);

  /**
   * Tells whether the user profile with this id already has an account.
   *
   * @param userId the id of the profile in User Service
   */
  boolean existsByUserId(Long userId);
}
