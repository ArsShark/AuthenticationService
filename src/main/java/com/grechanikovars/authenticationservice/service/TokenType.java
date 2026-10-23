package com.grechanikovars.authenticationservice.service;

/**
 * The kind of a token, written in its {@code token_type} claim.
 *
 * <p>The claim keeps a refresh token from being accepted as an access token and the other way
 * round: both are signed with the same key, so the signature alone cannot tell them apart. It is
 * a claim of its own and not the {@code typ} header of the JOSE standard, which says only that
 * the token is a JWT.
 */
enum TokenType {

  /** A short-lived token that proves who the caller is. */
  ACCESS("access"),

  /** A long-lived token that is only exchanged for a new pair of tokens. */
  REFRESH("refresh");

  private final String claimValue;

  TokenType(String claimValue) {
    this.claimValue = claimValue;
  }

  /** Returns the value of the {@code token_type} claim. */
  String claimValue() {
    return claimValue;
  }
}
