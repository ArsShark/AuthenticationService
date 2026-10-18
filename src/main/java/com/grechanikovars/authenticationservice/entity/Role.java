package com.grechanikovars.authenticationservice.entity;

/**
 * The role of an account. Every account has exactly one role.
 *
 * <p>The name of the constant is what is stored in the {@code credentials.role} column and what
 * the JWT carries in its {@code role} claim.
 */
public enum Role {

  /** Has access to all endpoints. */
  ADMIN,

  /** Has access only to its own resources. */
  USER
}
