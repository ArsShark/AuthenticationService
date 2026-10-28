package com.grechanikovars.authenticationservice.integration;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.security.InternalKeyAuthenticationFilter;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;

/**
 * Tests the deletion of an account by the id of its profile through HTTP, on a real PostgreSQL:
 * what the Gateway does to undo a registration.
 */
class CredentialDeletionIntegrationTest extends AbstractIntegrationTest {

  private static final String PATH = "/internal/credentials/by-user/{userId}";

  @Value("${app.internal.api-key}")
  private String internalKey;

  @Test
  void theAccountAndItsRefreshTokensAreDeletedAndOthersAreKept() throws Exception {
    long deleted = insertCredential("ann@example.com", "USER", 7L);
    long kept = insertCredential("bob@example.com", "USER", 8L);
    insertRefreshToken(UUID.randomUUID(), deleted);
    insertRefreshToken(UUID.randomUUID(), kept);

    mockMvc.perform(delete(PATH, 7L).header(InternalKeyAuthenticationFilter.HEADER, internalKey))
        .andExpect(status().isNoContent());

    assertAll(
        () -> assertEquals(1, countAccounts()),
        () -> assertEquals(0, count("SELECT count(*) FROM credentials WHERE user_id = 7")),
        () -> assertEquals(1, count("SELECT count(*) FROM credentials WHERE user_id = 8")),
        () -> assertEquals(1, count("SELECT count(*) FROM refresh_tokens")));
  }

  @Test
  void aRepeatedCallIsA404AndChangesNothing() throws Exception {
    insertCredential("ann@example.com", "USER", 7L);
    mockMvc.perform(delete(PATH, 7L).header(InternalKeyAuthenticationFilter.HEADER, internalKey))
        .andExpect(status().isNoContent());

    mockMvc.perform(delete(PATH, 7L).header(InternalKeyAuthenticationFilter.HEADER, internalKey))
        .andExpectAll(
            status().isNotFound(),
            jsonPath("$.detail").value("No account exists for this user"));

    assertEquals(0, countAccounts());
  }

  @Test
  void anAdminIsNeverDeletedEvenWithAMatchingProfileId() throws Exception {
    insertCredential("admin@example.com", "ADMIN", 9L);

    mockMvc.perform(delete(PATH, 9L).header(InternalKeyAuthenticationFilter.HEADER, internalKey))
        .andExpect(status().isNotFound());

    assertEquals(1, countAccounts());
  }

  @Test
  void withoutTheInternalKeyNothingIsDeleted() throws Exception {
    insertCredential("ann@example.com", "USER", 7L);

    mockMvc.perform(delete(PATH, 7L)).andExpect(status().isUnauthorized());
    mockMvc.perform(delete(PATH, 7L).header(InternalKeyAuthenticationFilter.HEADER, "wrong-key"))
        .andExpect(status().isUnauthorized());

    assertEquals(1, countAccounts());
  }

  private int count(String sql) {
    return Integer.valueOf(jdbcTemplate.queryForObject(sql, Integer.class));
  }
}
