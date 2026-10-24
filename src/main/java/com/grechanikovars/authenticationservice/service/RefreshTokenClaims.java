package com.grechanikovars.authenticationservice.service;

import java.time.Instant;
import java.util.UUID;

/**
 * What a valid refresh token says. It names the account and the token, and nothing more: the
 * role and the profile of the account are read from the database when the token is used, so a
 * change of the role takes effect at the next refresh.
 *
 * @param credentialId the id of the account in this service (the {@code sub} claim)
 * @param jti the id of the token, the key of its row in {@code refresh_tokens}
 * @param expiresAt the moment the token expires
 */
public record RefreshTokenClaims(long credentialId, UUID jti, Instant expiresAt) {
}
