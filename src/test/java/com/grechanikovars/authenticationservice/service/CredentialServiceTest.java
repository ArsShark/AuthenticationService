package com.grechanikovars.authenticationservice.service;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.grechanikovars.authenticationservice.TestEntities;
import com.grechanikovars.authenticationservice.dto.response.CredentialResponse;
import com.grechanikovars.authenticationservice.entity.Credential;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.exception.LoginAlreadyExistsException;
import com.grechanikovars.authenticationservice.exception.UserCredentialAlreadyExistsException;
import com.grechanikovars.authenticationservice.repository.CredentialRepository;
import com.grechanikovars.authenticationservice.service.CredentialService.AdminResult;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Unit tests of {@link CredentialService}: plain Mockito, no Spring, no database.
 *
 * <p>The credential id (42) and the user id (7) differ on purpose, so mixing them up fails a
 * test.
 */
@ExtendWith(MockitoExtension.class)
class CredentialServiceTest {

  private static final Long CREDENTIAL_ID = 42L;
  private static final Long USER_ID = 7L;
  private static final Instant CREATED_AT = Instant.parse("2026-10-19T10:00:00Z");
  private static final String PASSWORD = "s3cret-passw0rd";
  private static final String HASH = "h".repeat(60);

  @Mock
  private CredentialRepository credentialRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  private CredentialService service;

  @BeforeEach
  void setUp() {
    service = new CredentialService(credentialRepository, passwordEncoder);
  }

  @Test
  void registerStoresTheNormalizedLoginAndTheHashNeverThePassword() {
    when(passwordEncoder.encode(PASSWORD)).thenReturn(HASH);
    stubSaveAndFlush();

    CredentialResponse response = service.register("  Alice@Example.COM ", PASSWORD, USER_ID);

    ArgumentCaptor<Credential> saved = ArgumentCaptor.forClass(Credential.class);
    verify(credentialRepository).saveAndFlush(saved.capture());
    Credential credential = saved.getValue();
    assertAll(
        () -> assertEquals("alice@example.com", credential.getLogin()),
        () -> assertEquals(HASH, credential.getPasswordHash()),
        () -> assertEquals(Role.USER, credential.getRole()),
        () -> assertEquals(USER_ID, credential.getUserId()),
        () -> assertEquals(CREDENTIAL_ID, response.id()),
        () -> assertEquals("alice@example.com", response.login()),
        () -> assertEquals(Role.USER, response.role()),
        () -> assertEquals(USER_ID, response.userId()),
        () -> assertEquals(CREATED_AT, response.createdAt()));
  }

  @Test
  void registerNormalizesTheLoginIndependentOfTheDefaultLocale() {
    Locale original = Locale.getDefault();
    Locale.setDefault(Locale.forLanguageTag("tr-TR"));
    try {
      when(passwordEncoder.encode(PASSWORD)).thenReturn(HASH);
      stubSaveAndFlush();

      CredentialResponse response = service.register("INFO@EXAMPLE.COM", PASSWORD, USER_ID);

      assertEquals("info@example.com", response.login());
    } finally {
      Locale.setDefault(original);
    }
  }

  @Test
  void registerRejectsAnExistingLoginBeforeHashing() {
    when(credentialRepository.existsByLogin("alice@example.com")).thenReturn(true);

    assertThrows(LoginAlreadyExistsException.class,
        () -> service.register("Alice@Example.com", PASSWORD, USER_ID));

    verifyNoInteractions(passwordEncoder);
    verify(credentialRepository, never()).saveAndFlush(any(Credential.class));
  }

  @Test
  void registerRejectsAUserThatAlreadyHasAnAccountBeforeHashing() {
    when(credentialRepository.existsByUserId(USER_ID)).thenReturn(true);

    assertThrows(UserCredentialAlreadyExistsException.class,
        () -> service.register("alice@example.com", PASSWORD, USER_ID));

    verifyNoInteractions(passwordEncoder);
    verify(credentialRepository, never()).saveAndFlush(any(Credential.class));
  }

  @Test
  void registerDoesNotSwallowAUniqueViolationFromTheDatabase() {
    when(passwordEncoder.encode(PASSWORD)).thenReturn(HASH);
    when(credentialRepository.saveAndFlush(any(Credential.class)))
        .thenThrow(new DataIntegrityViolationException("duplicate"));

    assertThrows(DataIntegrityViolationException.class,
        () -> service.register("alice@example.com", PASSWORD, USER_ID));
  }

  @Test
  void createAdminStoresAnAdminWithoutAProfile() {
    when(passwordEncoder.encode(PASSWORD)).thenReturn(HASH);
    stubSaveAndFlush();

    AdminResult result = service.createAdminIfAbsent("  Admin@Example.COM ", PASSWORD);

    ArgumentCaptor<Credential> saved = ArgumentCaptor.forClass(Credential.class);
    verify(credentialRepository).saveAndFlush(saved.capture());
    Credential credential = saved.getValue();
    assertAll(
        () -> assertEquals(AdminResult.CREATED, result),
        () -> assertEquals("admin@example.com", credential.getLogin()),
        () -> assertEquals(HASH, credential.getPasswordHash()),
        () -> assertEquals(Role.ADMIN, credential.getRole()),
        () -> assertNull(credential.getUserId()));
  }

  @Test
  void createAdminLeavesAnExistingAdminAlone() {
    when(credentialRepository.findByLogin("admin@example.com"))
        .thenReturn(Optional.of(new Credential("admin@example.com", HASH, Role.ADMIN, null)));

    AdminResult result = service.createAdminIfAbsent("Admin@Example.com", PASSWORD);

    assertEquals(AdminResult.ADMIN_EXISTS, result);
    verifyNoInteractions(passwordEncoder);
    verify(credentialRepository, never()).saveAndFlush(any(Credential.class));
  }

  @Test
  void createAdminDoesNotTakeOverTheLoginOfAUser() {
    when(credentialRepository.findByLogin("admin@example.com"))
        .thenReturn(Optional.of(new Credential("admin@example.com", HASH, Role.USER, USER_ID)));

    AdminResult result = service.createAdminIfAbsent("admin@example.com", PASSWORD);

    assertEquals(AdminResult.LOGIN_TAKEN_BY_USER, result);
    verifyNoInteractions(passwordEncoder);
    verify(credentialRepository, never()).saveAndFlush(any(Credential.class));
  }

  /** Makes the repository behave like a database: it assigns the id and the audit times. */
  private void stubSaveAndFlush() {
    when(credentialRepository.saveAndFlush(any(Credential.class))).thenAnswer(invocation ->
        TestEntities.withDatabaseValues(invocation.getArgument(0), CREDENTIAL_ID, CREATED_AT));
  }
}
