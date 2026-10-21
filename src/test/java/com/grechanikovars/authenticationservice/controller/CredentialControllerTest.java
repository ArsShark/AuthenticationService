package com.grechanikovars.authenticationservice.controller;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.config.InternalApiConfig;
import com.grechanikovars.authenticationservice.config.SecurityConfig;
import com.grechanikovars.authenticationservice.dto.response.CredentialResponse;
import com.grechanikovars.authenticationservice.entity.Role;
import com.grechanikovars.authenticationservice.exception.LoginAlreadyExistsException;
import com.grechanikovars.authenticationservice.exception.UserCredentialAlreadyExistsException;
import com.grechanikovars.authenticationservice.security.InternalKeyInterceptor;
import com.grechanikovars.authenticationservice.service.CredentialService;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Tests the HTTP contract of {@link CredentialController}: the security chain, the internal key
 * interceptor, the controller, the validation and the error handler work together; the service
 * is a mock.
 */
@WebMvcTest(controllers = CredentialController.class,
    properties = "app.internal.api-key=test-internal-key",
    excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class)
@Import({SecurityConfig.class, InternalApiConfig.class})
class CredentialControllerTest {

  private static final String PATH = "/internal/credentials";
  private static final String KEY = "test-internal-key";
  private static final String PASSWORD = "s3cret-passw0rd";

  private static final String VALID_BODY = """
      {"login": "alice@example.com", "password": "s3cret-passw0rd", "userId": 7}
      """;
  private static final String INVALID_BODY = """
      {"login": "not-an-email", "password": "pw-1234", "userId": 0}
      """;

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private CredentialService credentialService;

  @Test
  void registerReturnsCreatedWithThePublicViewOfTheAccount() throws Exception {
    when(credentialService.register("alice@example.com", PASSWORD, 7L)).thenReturn(
        new CredentialResponse(42L, "alice@example.com", Role.USER, 7L,
            Instant.parse("2026-10-19T10:00:00Z")));

    mockMvc.perform(jsonPost(VALID_BODY).header(InternalKeyInterceptor.HEADER, KEY))
        .andExpectAll(
            status().isCreated(),
            header().doesNotExist(HttpHeaders.LOCATION),
            jsonPath("$.id").value(42),
            jsonPath("$.login").value("alice@example.com"),
            jsonPath("$.role").value("USER"),
            jsonPath("$.userId").value(7),
            jsonPath("$.createdAt").value("2026-10-19T10:00:00Z"),
            jsonPath("$.password").doesNotExist(),
            jsonPath("$.passwordHash").doesNotExist());

    verify(credentialService).register("alice@example.com", PASSWORD, 7L);
  }

  @Test
  void missingKeyIsUnauthorizedAndTheServiceIsNotCalled() throws Exception {
    mockMvc.perform(jsonPost(VALID_BODY)).andExpectAll(
        status().isUnauthorized(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(401),
        jsonPath("$.detail").value("Missing or invalid internal key"));

    verifyNoInteractions(credentialService);
  }

  @Test
  void wrongKeyIsUnauthorizedAndTheServiceIsNotCalled() throws Exception {
    mockMvc.perform(jsonPost(VALID_BODY).header(InternalKeyInterceptor.HEADER, "wrong-key"))
        .andExpectAll(
            status().isUnauthorized(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    verifyNoInteractions(credentialService);
  }

  /** The key is checked before the body is read, so the caller learns nothing about the body. */
  @Test
  void wrongKeyBeatsAnInvalidBody() throws Exception {
    mockMvc.perform(jsonPost(INVALID_BODY).header(InternalKeyInterceptor.HEADER, "wrong-key"))
        .andExpect(status().isUnauthorized());

    verifyNoInteractions(credentialService);
  }

  @Test
  void invalidBodyIsBadRequestWithoutRejectedValuesAndTheServiceIsNotCalled() throws Exception {
    MvcResult result = mockMvc
        .perform(jsonPost(INVALID_BODY).header(InternalKeyInterceptor.HEADER, KEY))
        .andExpectAll(
            status().isBadRequest(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
            jsonPath("$.errors.length()").value(3),
            jsonPath("$.errors[0].field").value("login"),
            jsonPath("$.errors[1].field").value("password"),
            jsonPath("$.errors[2].field").value("userId"))
        .andReturn();

    String response = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    assertAll(
        () -> assertFalse(response.contains("not-an-email")),
        () -> assertFalse(response.contains("pw-1234")));
    verifyNoInteractions(credentialService);
  }

  @Test
  void malformedJsonIsBadRequest() throws Exception {
    mockMvc.perform(jsonPost("{not json").header(InternalKeyInterceptor.HEADER, KEY))
        .andExpectAll(
            status().isBadRequest(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));

    verifyNoInteractions(credentialService);
  }

  @Test
  void takenLoginIsConflict() throws Exception {
    when(credentialService.register("alice@example.com", PASSWORD, 7L))
        .thenThrow(new LoginAlreadyExistsException());

    mockMvc.perform(jsonPost(VALID_BODY).header(InternalKeyInterceptor.HEADER, KEY))
        .andExpectAll(
            status().isConflict(),
            jsonPath("$.detail").value(LoginAlreadyExistsException.MESSAGE));
  }

  @Test
  void userThatAlreadyHasAnAccountIsConflict() throws Exception {
    when(credentialService.register("alice@example.com", PASSWORD, 7L))
        .thenThrow(new UserCredentialAlreadyExistsException());

    mockMvc.perform(jsonPost(VALID_BODY).header(InternalKeyInterceptor.HEADER, KEY))
        .andExpectAll(
            status().isConflict(),
            jsonPath("$.detail").value(UserCredentialAlreadyExistsException.MESSAGE));
  }

  @Test
  void unexpectedErrorIsInternalServerErrorWithoutDetails() throws Exception {
    when(credentialService.register("alice@example.com", PASSWORD, 7L))
        .thenThrow(new IllegalStateException("secret internal detail"));

    MvcResult result = mockMvc
        .perform(jsonPost(VALID_BODY).header(InternalKeyInterceptor.HEADER, KEY))
        .andExpectAll(
            status().isInternalServerError(),
            jsonPath("$.detail").value("An unexpected error occurred"))
        .andReturn();

    assertFalse(result.getResponse().getContentAsString(StandardCharsets.UTF_8)
        .contains("secret internal detail"));
  }

  @Test
  void getIsMethodNotAllowed() throws Exception {
    mockMvc.perform(get(PATH).header(InternalKeyInterceptor.HEADER, KEY))
        .andExpect(status().isMethodNotAllowed());
  }

  /**
   * The route that the Gateway opens to the outside must not lead to this endpoint. The closed
   * security chain answers an anonymous caller with 401 before Spring MVC sees the request; the
   * key header means nothing outside {@code /internal}.
   */
  @Test
  void theEndpointIsNotUnderTheAuthApiPath() throws Exception {
    mockMvc.perform(get("/api/auth/credentials").header(InternalKeyInterceptor.HEADER, KEY))
        .andExpect(status().isUnauthorized());
    verifyNoInteractions(credentialService);
  }

  private static MockHttpServletRequestBuilder jsonPost(String body) {
    return post(PATH).contentType(MediaType.APPLICATION_JSON).content(body);
  }
}
