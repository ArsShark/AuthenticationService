package com.innowise.authservice.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.innowise.authservice.TestEntities;
import com.innowise.authservice.dto.response.CredentialResponse;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.CredentialNotFoundException;
import com.innowise.authservice.exception.LoginAlreadyExistsException;
import com.innowise.authservice.exception.UserCredentialAlreadyExistsException;
import com.innowise.authservice.mapper.CredentialMapperImpl;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.service.CredentialService.AdminResult;
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
    service = new CredentialService(credentialRepository, passwordEncoder,
        new CredentialMapperImpl());
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
        () -> assertEquals("alice@example.com", credential.getUsername()),
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
    when(credentialRepository.existsByUsername("alice@example.com")).thenReturn(true);

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
        () -> assertEquals("admin@example.com", credential.getUsername()),
        () -> assertEquals(HASH, credential.getPasswordHash()),
        () -> assertEquals(Role.ADMIN, credential.getRole()),
        () -> assertNull(credential.getUserId()));
  }

  @Test
  void createAdminLeavesAnExistingAdminAlone() {
    when(credentialRepository.findByUsername("admin@example.com"))
        .thenReturn(Optional.of(new Credential("admin@example.com", HASH, Role.ADMIN, null)));

    AdminResult result = service.createAdminIfAbsent("Admin@Example.com", PASSWORD);

    assertEquals(AdminResult.ADMIN_EXISTS, result);
    verifyNoInteractions(passwordEncoder);
    verify(credentialRepository, never()).saveAndFlush(any(Credential.class));
  }

  @Test
  void createAdminDoesNotTakeOverTheLoginOfAUser() {
    when(credentialRepository.findByUsername("admin@example.com"))
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

  @Test
  void deleteByUserIdDeletesTheAccountOfAUserAndNeverOfAnAdmin() {
    when(credentialRepository.deleteByUserIdAndRole(USER_ID, Role.USER)).thenReturn(1L);

    service.deleteByUserId(USER_ID);

    verify(credentialRepository).deleteByUserIdAndRole(USER_ID, Role.USER);
    verifyNoMoreInteractions(credentialRepository);
  }

  @Test
  void deleteByUserIdOfAProfileWithoutAnAccountIsNotFound() {
    when(credentialRepository.deleteByUserIdAndRole(USER_ID, Role.USER)).thenReturn(0L);

    assertThrows(CredentialNotFoundException.class, () -> service.deleteByUserId(USER_ID));
  }
}
