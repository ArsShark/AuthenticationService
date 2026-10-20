package com.grechanikovars.authenticationservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * A refresh token that the service has issued.
 *
 * <p>Only the {@code jti} claim is stored, never the token itself: a signed token cannot be
 * rebuilt from its id. A token is valid while {@code revokedAt} is {@code null}. The revocation
 * is done by one atomic bulk update (rotation and reuse detection), not by changing the entity,
 * so there is no setter.
 */
@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken extends AuditableEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  /** The {@code jti} claim of the token. */
  @Column(name = "jti", nullable = false)
  private UUID jti;

  /** The account the token belongs to. */
  @ManyToOne(fetch = FetchType.LAZY, optional = false)
  @JoinColumn(name = "credential_id", nullable = false)
  private Credential credential;

  /** The moment the token expires; the same value as its {@code exp} claim. */
  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  /** The moment the token was used or revoked; {@code null} while the token is valid. */
  @Column(name = "revoked_at")
  private Instant revokedAt;

  /**
   * Creates a new, valid token record.
   *
   * @param jti the {@code jti} claim of the issued token
   * @param credential the account the token belongs to
   * @param expiresAt the moment the token expires
   */
  public RefreshToken(UUID jti, Credential credential, Instant expiresAt) {
    this.jti = jti;
    this.credential = credential;
    this.expiresAt = expiresAt;
  }
}
