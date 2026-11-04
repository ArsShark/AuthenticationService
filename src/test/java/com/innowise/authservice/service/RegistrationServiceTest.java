package com.innowise.authservice.service;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.innowise.authservice.client.InternalUserRequest;
import com.innowise.authservice.client.InternalUserResponse;
import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.LoginAlreadyExistsException;
import com.innowise.authservice.exception.UserServiceTimeoutException;
import com.innowise.authservice.exception.UserServiceUnavailableException;
import java.time.LocalDate;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests the order of the registration and the undoing. The profile id (31) differs from every
 * other number, so mixing it up fails a test. The request has an email in mixed case and the
 * User Service answers with the stored lowercase form: the account must use the stored form.
 * The profile is always undone by the registration id that the creation sent.
 */
@ExtendWith(MockitoExtension.class)
class RegistrationServiceTest {

  private static final String PASSWORD = "s3cret-passw0rd";
  private static final RegisterRequest REQUEST = new RegisterRequest(
      "Alice", "Smith", LocalDate.of(1990, 5, 17), "Alice@Example.com", PASSWORD);
  private static final InternalUserResponse CREATED = new InternalUserResponse(
      31L, "Alice", "Smith", LocalDate.of(1990, 5, 17), "alice@example.com");

  @Mock
  private UserServiceClient users;

  @Mock
  private CredentialService credentials;

  private RegistrationService service() {
    return new RegistrationService(users, credentials);
  }

  /** The registration id that the creation of the profile was called with (exactly once). */
  private UUID sentRegistrationId() {
    ArgumentCaptor<UUID> id = ArgumentCaptor.forClass(UUID.class);
    verify(users).create(any(), id.capture());
    return id.getValue();
  }

  @Test
  void createsTheProfileThenSavesTheAccountWithTheStoredEmail() {
    when(users.create(any(), any())).thenReturn(CREATED);

    RegisterResponse response = service().register(REQUEST);

    InOrder order = inOrder(users, credentials);
    assertAll(
        () -> assertEquals(new RegisterResponse(
            31L, "Alice", "Smith", LocalDate.of(1990, 5, 17), "alice@example.com"), response),
        () -> order.verify(users).create(eq(new InternalUserRequest(
            "Alice", "Smith", LocalDate.of(1990, 5, 17), "Alice@Example.com")), any(UUID.class)),
        () -> order.verify(credentials).register("alice@example.com", PASSWORD, 31L),
        () -> verify(users, never()).deleteByRegistrationId(any()));
  }

  @Test
  void aTakenEmailInTheUserServiceLeavesNothingToUndo() {
    when(users.create(any(), any())).thenThrow(new EmailAlreadyRegisteredException());

    assertAll(
        () -> assertThrows(EmailAlreadyRegisteredException.class,
            () -> service().register(REQUEST)),
        () -> verifyNoInteractions(credentials),
        () -> verify(users, never()).deleteByRegistrationId(any()));
  }

  @Test
  void aUserServiceThatDoesNotAnswerLeavesNothingToUndo() {
    when(users.create(any(), any())).thenThrow(new UserServiceTimeoutException());

    assertAll(
        () -> assertThrows(UserServiceTimeoutException.class, () -> service().register(REQUEST)),
        () -> verifyNoInteractions(credentials),
        () -> verify(users, never()).deleteByRegistrationId(any()));
  }

  /** The login may be held by an account whose profile is gone: the new profile must go. */
  @Test
  void aTakenLoginDeletesTheProfileAndIsAConflict() {
    when(users.create(any(), any())).thenReturn(CREATED);
    doThrow(new LoginAlreadyExistsException())
        .when(credentials).register(anyString(), anyString(), anyLong());

    EmailAlreadyRegisteredException error = assertThrows(EmailAlreadyRegisteredException.class,
        () -> service().register(REQUEST));

    assertAll(
        () -> assertEquals(EmailAlreadyRegisteredException.MESSAGE, error.getMessage()),
        () -> verify(users).deleteByRegistrationId(sentRegistrationId()));
  }

  @Test
  void anyOtherFailureOfTheAccountDeletesTheProfileAndKeepsTheOriginalError() {
    when(users.create(any(), any())).thenReturn(CREATED);
    IllegalStateException failure = new IllegalStateException("database is down");
    doThrow(failure).when(credentials).register(anyString(), anyString(), anyLong());

    IllegalStateException thrown = assertThrows(IllegalStateException.class,
        () -> service().register(REQUEST));

    assertAll(
        () -> assertSame(failure, thrown),
        () -> verify(users).deleteByRegistrationId(sentRegistrationId()));
  }

  /** A failed undoing is logged, and the caller still sees why the registration failed. */
  @Test
  void aFailedDeletionDoesNotHideTheOriginalError() {
    when(users.create(any(), any())).thenReturn(CREATED);
    doThrow(new LoginAlreadyExistsException())
        .when(credentials).register(anyString(), anyString(), anyLong());
    doThrow(new UserServiceUnavailableException()).when(users).deleteByRegistrationId(any());

    RuntimeException thrown = assertThrows(RuntimeException.class,
        () -> service().register(REQUEST));

    assertInstanceOf(EmailAlreadyRegisteredException.class, thrown);
  }

  @Test
  void aFailedDeletionDoesNotHideAnUnexpectedError() {
    when(users.create(any(), any())).thenReturn(CREATED);
    IllegalStateException failure = new IllegalStateException("database is down");
    doThrow(failure).when(credentials).register(anyString(), anyString(), anyLong());
    doThrow(new UserServiceTimeoutException()).when(users).deleteByRegistrationId(any());

    assertSame(failure, assertThrows(IllegalStateException.class,
        () -> service().register(REQUEST)));
  }

  /** Every attempt has its own id: the undoing of one never removes the profile of another. */
  @Test
  void everyRegistrationUsesItsOwnId() {
    when(users.create(any(), any())).thenReturn(CREATED);
    ArgumentCaptor<UUID> ids = ArgumentCaptor.forClass(UUID.class);

    service().register(REQUEST);
    service().register(REQUEST);

    verify(users, times(2)).create(any(), ids.capture());
    assertNotEquals(ids.getAllValues().get(0), ids.getAllValues().get(1));
  }
}
