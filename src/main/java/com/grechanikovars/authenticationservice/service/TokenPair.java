package com.grechanikovars.authenticationservice.service;

/**
 * An access token and the refresh token that was issued together with it.
 *
 * <p>The generated {@code toString()} is safe: it uses the one of {@link IssuedToken}, which
 * hides the value of the token.
 *
 * @param access the short-lived token that proves who the caller is
 * @param refresh the long-lived token that is exchanged for a new pair
 */
public record TokenPair(IssuedToken access, IssuedToken refresh) {
}
