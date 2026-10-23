package com.grechanikovars.authenticationservice.repository;

import com.grechanikovars.authenticationservice.entity.RefreshToken;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * Stores {@link RefreshToken} rows and revokes them.
 *
 * <p>Both revoking methods are bulk updates: each is one SQL statement, so the database decides
 * who wins when several requests use the same token at once. A bulk update bypasses JPA Auditing,
 * so {@code updated_at} is set explicitly from the value that the caller passes (the application
 * clock). A bulk update also needs a running transaction: the caller provides it.
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

  /**
   * Revokes one token, but only if it is still valid.
   *
   * <p>This is the atomic step of a token rotation. The condition {@code revoked_at IS NULL} is
   * evaluated by the database under a row lock, so of several parallel calls with the same
   * {@code jti} exactly one gets {@code 1}; the others wait for the lock, see the committed
   * change and get {@code 0}.
   *
   * @param jti the {@code jti} claim of the token
   * @param now the moment of the revocation, from the application clock
   * @return {@code 1} if this call revoked the token; {@code 0} if the token was already revoked
   *     or is unknown
   */
  @Modifying
  @Query("""
      UPDATE RefreshToken t
      SET t.revokedAt = :now, t.updatedAt = :now
      WHERE t.jti = :jti AND t.revokedAt IS NULL
      """)
  int revokeByJti(@Param("jti") UUID jti, @Param("now") Instant now);

  /**
   * Revokes every valid token of an account. Tokens that are already revoked keep the moment of
   * their own revocation.
   *
   * @param credentialId the id of the account
   * @param now the moment of the revocation, from the application clock
   * @return the number of tokens that were revoked by this call
   */
  @Modifying
  @Query("""
      UPDATE RefreshToken t
      SET t.revokedAt = :now, t.updatedAt = :now
      WHERE t.credential.id = :credentialId AND t.revokedAt IS NULL
      """)
  int revokeAllByCredentialId(@Param("credentialId") Long credentialId,
      @Param("now") Instant now);
}
