package com.innowise.authservice.dto.response;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Pins what the public view of an account contains. How it is filled is tested in
 * {@code CredentialMapperTest}.
 */
class CredentialResponseTest {

  /** A new component here must be a conscious decision: the hash must never be added. */
  @Test
  void responseHasNoPasswordHash() {
    List<String> components = Arrays.stream(CredentialResponse.class.getRecordComponents())
        .map(RecordComponent::getName)
        .toList();

    assertEquals(List.of("id", "login", "role", "userId", "createdAt"), components);
  }
}
