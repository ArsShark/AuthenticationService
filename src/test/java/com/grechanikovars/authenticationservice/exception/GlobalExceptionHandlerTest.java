package com.grechanikovars.authenticationservice.exception;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.grechanikovars.authenticationservice.dto.request.CredentialRequest;
import jakarta.validation.Valid;
import java.nio.charset.StandardCharsets;
import org.hibernate.exception.ConstraintViolationException;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Tests {@link GlobalExceptionHandler} with a standalone MockMvc and a throwaway controller: no
 * Spring context, no database. The real constraint names are proved in the HTTP integration
 * tests.
 */
class GlobalExceptionHandlerTest {

  private ThrowingController controller;
  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    // The parameter interpolator needs no Jakarta EL implementation on the test classpath.
    LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
    validator.setMessageInterpolator(new ParameterMessageInterpolator());
    validator.afterPropertiesSet();
    controller = new ThrowingController();
    mockMvc = MockMvcBuilders.standaloneSetup(controller)
        .setControllerAdvice(new GlobalExceptionHandler())
        .setValidator(validator)
        .build();
  }

  @Test
  void takenLoginIsConflict() throws Exception {
    controller.toThrow = new LoginAlreadyExistsException();

    mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isConflict(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(409),
        jsonPath("$.detail").value(LoginAlreadyExistsException.MESSAGE));
  }

  @Test
  void userWithAnAccountIsConflict() throws Exception {
    controller.toThrow = new UserCredentialAlreadyExistsException();

    mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isConflict(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(409),
        jsonPath("$.detail").value(UserCredentialAlreadyExistsException.MESSAGE));
  }

  /** A wrong internal key is an authentication failure: the same 401, nothing about the key. */
  @Test
  void invalidInternalKeyIsUnauthorizedWithAConstantDetail() throws Exception {
    controller.toThrow = new InvalidInternalKeyException();

    MvcResult result = mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isUnauthorized(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(401),
        jsonPath("$.detail").value("Authentication is required")).andReturn();

    assertFalse(bodyOf(result).contains("internal key"));
  }

  @Test
  void authenticationFailureIsUnauthorizedWithAConstantDetail() throws Exception {
    controller.toThrow = new BadCredentialsException("this message must not reach the client");

    MvcResult result = mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isUnauthorized(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(401),
        jsonPath("$.detail").value("Authentication is required")).andReturn();

    assertFalse(bodyOf(result).contains("must not reach the client"));
  }

  @Test
  void accessDeniedIsForbiddenWithAConstantDetail() throws Exception {
    controller.toThrow = new AccessDeniedException("this message must not reach the client");

    MvcResult result = mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isForbidden(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(403),
        jsonPath("$.detail").value("Access is denied")).andReturn();

    assertFalse(bodyOf(result).contains("must not reach the client"));
  }

  @Test
  void lostRaceOnTheUniqueLoginIsConflict() throws Exception {
    controller.toThrow = integrityViolation("uq_credentials_login", "irrelevant");

    mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isConflict(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.detail").value(LoginAlreadyExistsException.MESSAGE));
  }

  @Test
  void lostRaceOnTheUniqueUserIdIsConflict() throws Exception {
    controller.toThrow = integrityViolation("uq_credentials_user_id", "irrelevant");

    mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isConflict(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.detail").value(UserCredentialAlreadyExistsException.MESSAGE));
  }

  @Test
  void otherIntegrityViolationIsInternalServerErrorWithoutDetails() throws Exception {
    controller.toThrow = integrityViolation("ck_credentials_role", "Key (password_hash)=(abc123)");

    MvcResult result = mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isInternalServerError(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(500),
        jsonPath("$.detail").value("An unexpected error occurred")).andReturn();

    assertFalse(bodyOf(result).contains("abc123"));
  }

  @Test
  void integrityViolationWithoutAConstraintNameIsInternalServerError() throws Exception {
    controller.toThrow = new DataIntegrityViolationException("Key (login)=(bob@example.com)");

    MvcResult result = mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isInternalServerError(),
        jsonPath("$.detail").value("An unexpected error occurred")).andReturn();

    assertFalse(bodyOf(result).contains("bob@example.com"));
  }

  @Test
  void unexpectedExceptionIsInternalServerErrorWithoutDetails() throws Exception {
    controller.toThrow = new IllegalStateException("secret internal detail");

    MvcResult result = mockMvc.perform(get("/test/throw")).andExpectAll(
        status().isInternalServerError(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(500),
        jsonPath("$.detail").value("An unexpected error occurred")).andReturn();

    assertFalse(bodyOf(result).contains("secret internal detail"));
  }

  @Test
  void invalidBodyListsEveryFieldSortedAndWithoutRejectedValues() throws Exception {
    String body = """
        {"login": "not-an-email", "password": "pw-1234", "userId": 0}
        """;

    MvcResult result = mockMvc.perform(
        post("/test/validate").contentType(MediaType.APPLICATION_JSON).content(body))
        .andExpectAll(
            status().isBadRequest(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
            jsonPath("$.status").value(400),
            jsonPath("$.errors.length()").value(3),
            jsonPath("$.errors[0].field").value("login"),
            jsonPath("$.errors[1].field").value("password"),
            jsonPath("$.errors[2].field").value("userId"))
        .andReturn();

    String response = bodyOf(result);
    assertAll(
        () -> assertFalse(response.contains("not-an-email")),
        () -> assertFalse(response.contains("pw-1234")));
  }

  @Test
  void malformedJsonIsBadRequestInTheSameFormat() throws Exception {
    mockMvc.perform(post("/test/validate").contentType(MediaType.APPLICATION_JSON)
        .content("{not json")).andExpectAll(
            status().isBadRequest(),
            content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
            jsonPath("$.status").value(400));
  }

  @Test
  void wrongMethodIsMethodNotAllowedInTheSameFormat() throws Exception {
    mockMvc.perform(get("/test/validate")).andExpectAll(
        status().isMethodNotAllowed(),
        content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON),
        jsonPath("$.status").value(405));
  }

  /**
   * Builds the exception that Spring Data throws for a constraint: the Hibernate exception with the
   * constraint name is a cause of it. The Hibernate exception is a mock, so the test does not
   * depend on its constructors.
   */
  private static DataIntegrityViolationException integrityViolation(String constraint,
      String message) {
    ConstraintViolationException cause = mock(ConstraintViolationException.class);
    when(cause.getConstraintName()).thenReturn(constraint);
    return new DataIntegrityViolationException(message, cause);
  }

  private static String bodyOf(MvcResult result) throws Exception {
    return result.getResponse().getContentAsString(StandardCharsets.UTF_8);
  }

  /**
   * A throwaway controller: it throws what the test sets, and validates a request body. Since
   * Spring 6 a type-level {@code @RequestMapping} alone does not make a handler, so it is a
   * {@code @RestController}; it is nested in a test class, so Spring Boot keeps it out of the
   * component scan of the real application contexts.
   */
  @RestController
  @RequestMapping("/test")
  static class ThrowingController {

    private Exception toThrow;

    @GetMapping("/throw")
    String thrown() throws Exception {
      throw toThrow;
    }

    @PostMapping("/validate")
    String validate(@Valid @RequestBody CredentialRequest request) {
      return "valid";
    }
  }
}
