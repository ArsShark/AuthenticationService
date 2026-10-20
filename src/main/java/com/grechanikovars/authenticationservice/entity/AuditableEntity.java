package com.grechanikovars.authenticationservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import java.time.Instant;
import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

/**
 * Base class of all entities: adds the {@code created_at} and {@code updated_at} columns.
 *
 * <p>Both values are filled by JPA Auditing and have no setters. Subclasses declare their own
 * {@code id}. Bulk updates ({@code @Modifying} queries) bypass auditing, so a service that uses
 * them must pass {@code updated_at} explicitly.
 */
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
@Getter
public abstract class AuditableEntity {

  /** The moment the row was created. */
  @CreatedDate
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  /** The moment the row was last changed. */
  @LastModifiedDate
  @Column(name = "updated_at", nullable = false)
  private Instant updatedAt;
}
