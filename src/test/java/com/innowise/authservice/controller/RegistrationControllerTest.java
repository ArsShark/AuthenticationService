package com.innowise.authservice.controller;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.innowise.authservice.config.SecurityConfig;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.exception.EmailAlreadyRegisteredException;
import com.innowise.authservice.exception.UserServiceTimeoutException;
import com.innowise.authservice.exception.UserServiceUnavailableException;
import com.innowise.authservice.service.RegistrationService;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Tests the HTTP contract of {@link RegistrationController}: the security chain, the controller,
 * the validation and the error handler work together; the service is a mock.
 */
@WebMvcTest(controllers = RegistrationController.class,
    properties = "app.internal.api-key=test-internal-key",
    excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class)
@Import(SecurityConfig.class)
class RegistrationControllerTest {

  private static final String PATH = "/api/auth/register";
  private static final String PASSWORD = "s3cret-passw0rd";

  private static final String VALID_BODY = """
      {"name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
       "email": "Alice@Example.com", "password": "s3cret-passw0rd"}
      """;

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private RegistrationService registrationService;

  private ResultActions register(String body) throws Exception {
    return mockMvc.perform(post(PATH).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  /** The registration is open to everybody: no token and no key are sent. */
  @Test
  void registerReturns201WithTheProfileAndNoSecrets() throws Exception {
    when(registrationService.register(any())).thenReturn(new RegisterResponse(
        31L, "Alice", "Smith", LocalDate.of(1990, 5, 17), "alice@example.com"));

    String body = register(VALID_BODY)
        .andExpectAll(
            status().isCreated(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON),
            jsonPath("$.id").value(31),
            jsonPath("$.email").value("alice@example.com"),
            jsonPath("$.birthDate").value("1990-05-17"),
            jsonPath("$.password").doesNotExist(),
            jsonPath("$.accessToken").doesNotExist())
        .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

    assertAll(
        () -> assertFalse(body.contains(PASSWORD)),
        () -> verify(registrationService).register(new RegisterRequest(
            "Alice", "Smith", LocalDate.of(1990, 5, 17), "Alice@Example.com", PASSWORD)));
  }

  @Test
  void anInvalidBodyIs400WithSortedFieldsAndNoValues() throws Exception {
    register("""
        {"name": " ", "surname": "Smith", "birthDate": "2999-01-01",
         "email": "not-an-email", "password": "short"}
        """).andExpectAll(
            status().isBadRequest(),
            jsonPath("$.errors[0].field").value("birthDate"),
            jsonPath("$.errors[1].field").value("email"),
            jsonPath("$.errors[2].field").value("name"),
            jsonPath("$.errors[3].field").value("password"),
            content().string(org.hamcrest.Matchers.not(
                org.hamcrest.Matchers.containsString("not-an-email"))));

    verifyNoInteractions(registrationService);
  }

  @Test
  void aMissingFieldIs400() throws Exception {
    register("""
        {"name": "Alice", "surname": "Smith", "birthDate": "1990-05-17",
         "email": "alice@example.com"}
        """).andExpectAll(
            status().isBadRequest(),
            jsonPath("$.errors[0].field").value("password"));

    verifyNoInteractions(registrationService);
  }

  @Test
  void aBodyThatIsNotJsonIs400() throws Exception {
    register("not json").andExpect(status().isBadRequest());

    verifyNoInteractions(registrationService);
  }

  @Test
  void aTakenEmailIs409() throws Exception {
    when(registrationService.register(any())).thenThrow(new EmailAlreadyRegisteredException());

    register(VALID_BODY).andExpectAll(
        status().isConflict(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.detail").value(EmailAlreadyRegisteredException.MESSAGE));
  }

  @Test
  void aUserServiceThatIsNotAvailableIs502() throws Exception {
    when(registrationService.register(any())).thenThrow(new UserServiceUnavailableException(true));

    register(VALID_BODY).andExpectAll(
        status().isBadGateway(),
        jsonPath("$.detail").value(UserServiceUnavailableException.MESSAGE));
  }

  @Test
  void aUserServiceThatIsTooSlowIs504() throws Exception {
    when(registrationService.register(any())).thenThrow(new UserServiceTimeoutException(true));

    register(VALID_BODY).andExpectAll(
        status().isGatewayTimeout(),
        jsonPath("$.detail").value(UserServiceTimeoutException.MESSAGE));
  }

  /** Only POST is open; another method on the same path stays closed. */
  @Test
  void otherMethodsOnThePathAreClosed() throws Exception {
    mockMvc.perform(get(PATH)).andExpect(status().isUnauthorized());

    verifyNoInteractions(registrationService);
  }
}
