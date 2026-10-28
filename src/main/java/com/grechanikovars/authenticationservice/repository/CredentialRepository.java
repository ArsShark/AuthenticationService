package com.grechanikovars.authenticationservice.repository;

import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
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

  /**
   * Deletes the accounts of a user profile that have the given role. The refresh tokens of the
   * account go with it: the foreign key of {@code refresh_tokens} is {@code ON DELETE CASCADE}.
   *
   * <p>The caller must provide a transaction. The role is a parameter, so a caller that passes
   * {@link Role#USER} can never delete an admin.
   *
   * @param userId the id of the profile in User Service
   * @param role the role of the accounts to delete
   * @return the number of deleted accounts (0 or 1: the user id is unique)
   */
  long deleteByUserIdAndRole(Long userId, Role role);
}
