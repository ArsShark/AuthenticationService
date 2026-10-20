package com.grechanikovars.authenticationservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * The login data of one account: login, password hash, role and the link to the user profile.
 *
 * <p>The entity is immutable on purpose: nothing in the service changes these fields after the
 * account is created, so there are no setters. A feature that needs a change (a password change,
 * for example) adds one explicit method. There is no {@code toString()} either, so the hash
 * cannot reach a log by accident.
 */
@Entity
@Table(name = "credentials")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Credential extends AuditableEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  /** The email of the account in lowercase; the service normalizes it before it gets here. */
  @Column(name = "login", nullable = false, length = 255)
  private String login;

  /** The BCrypt hash: always 60 characters, the salt is inside. Never log or return it. */
  @Column(name = "password_hash", nullable = false, length = 60)
  private String passwordHash;

  @Enumerated(EnumType.STRING)
  @Column(name = "role", nullable = false, length = 20)
  private Role role;

  /**
   * The id of the profile in User Service. Empty only for an {@link Role#ADMIN} that has no
   * profile; the database enforces this with a CHECK constraint.
   */
  @Column(name = "user_id")
  private Long userId;

  /**
   * Creates a new account.
   *
   * @param login the normalized email
   * @param passwordHash the BCrypt hash of the password, never the password itself
   * @param role the role of the account
   * @param userId the id of the profile in User Service, or {@code null} for an admin without one
   */
  public Credential(String login, String passwordHash, Role role, Long userId) {
    this.login = login;
    this.passwordHash = passwordHash;
    this.role = role;
    this.userId = userId;
  }
}
