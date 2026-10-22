package com.grechanikovars.authenticationservice;

import com.grechanikovars.authenticationservice.entity.Credential;
import java.time.Instant;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Helpers for tests that work with entities without a database.
 *
 * <p>The entities have no setters on purpose, so the values that the database and JPA Auditing
 * fill in a real run are set through reflection here.
 */
public final class TestEntities {

  private TestEntities() {
  }

  /**
   * Fills the id and the audit timestamps of an account, as the database and JPA Auditing would.
   *
   * @return the same account
   */
  public static Credential withDatabaseValues(Credential credential, Long id, Instant now) {
    ReflectionTestUtils.setField(credential, "id", id);
    ReflectionTestUtils.setField(credential, "createdAt", now);
    ReflectionTestUtils.setField(credential, "updatedAt", now);
    return credential;
  }
}
