package com.grechanikovars.authenticationservice.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.service.AccessTokenClaims;
import java.time.Instant;

/**
 * The answer to a token validation, in the style of token introspection: the token is either
 * valid, and then the answer says who it belongs to, or it is not, and then the answer is just
 * {@code {"valid": false}}.
 *
 * <p>Empty fields are left out of the JSON. A token that is not valid gets no reason: a client
 * must not learn whether the token was garbage, expired, of the wrong type or signed by someone
 * else. The email and the id of the account are not part of the answer.
 *
 * @param valid whether the token is a valid access token
 * @param userId the id of the user in the User Service; absent for a token that is not valid
 *     and for an admin who has no profile
 * @param role the role of the account; absent for a token that is not valid
 * @param expiresAt the moment when the token stops being valid; absent for a token that is not
 *     valid
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ValidationResponse(boolean valid, Long userId, Role role, Instant expiresAt) {

  private static final ValidationResponse INVALID =
      new ValidationResponse(false, null, null, null);

  /**
   * Describes a valid token.
   *
   * @param claims the claims of a token that passed every check
   * @return the answer with the user, the role and the expiry
   */
  public static ValidationResponse of(AccessTokenClaims claims) {
    return new ValidationResponse(true, claims.userId(), claims.role(), claims.expiresAt());
  }

  /**
   * Describes a token that is not valid, whatever the reason.
   *
   * @return the answer with nothing but {@code valid = false}
   */
  public static ValidationResponse invalid() {
    return INVALID;
  }
}
