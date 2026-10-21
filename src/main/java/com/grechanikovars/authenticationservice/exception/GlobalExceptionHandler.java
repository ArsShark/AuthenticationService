package com.grechanikovars.authenticationservice.exception;

import com.grechanikovars.authenticationservice.dto.response.FieldViolation;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Turns every exception of the controller layer into an RFC 9457 {@link ProblemDetail}
 * ({@code application/problem+json}).
 *
 * <p>The class extends {@link ResponseEntityExceptionHandler}, so the errors of Spring MVC itself
 * (malformed JSON, wrong method, unknown path) use the same format. Responses and logs never
 * contain rejected values or the messages of unexpected exceptions: they may hold a login or a
 * password hash.
 *
 * <p>The security exceptions are answered here too. Those of the filter chain get here through
 * {@code ProblemDetailSecurityHandler}; those thrown inside a controller arrive directly, and
 * without explicit handlers the catch-all would turn them into a 500.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

  private static final Logger LOGGER = LogManager.getLogger(GlobalExceptionHandler.class);

  private static final String AUTHENTICATION_REQUIRED = "Authentication is required";
  private static final String ACCESS_DENIED = "Access is denied";

  /** The UNIQUE constraints of the database and the detail for the client when one is violated. */
  private static final Map<String, String> UNIQUE_CONSTRAINT_DETAILS = Map.of(
      ViolatedConstraint.UNIQUE_LOGIN, LoginAlreadyExistsException.MESSAGE,
      ViolatedConstraint.UNIQUE_USER_ID, UserCredentialAlreadyExistsException.MESSAGE);

  /**
   * Handles a taken login or a user that already has an account.
   *
   * @param ex the rejection of the service
   * @return 409
   */
  @ExceptionHandler({LoginAlreadyExistsException.class,
      UserCredentialAlreadyExistsException.class})
  public ResponseEntity<ProblemDetail> handleConflict(RuntimeException ex) {
    return reject(HttpStatus.CONFLICT, ex.getMessage(), ex);
  }

  /**
   * Handles a caller that is not authenticated.
   *
   * <p>The detail is a constant and never says why: a missing and a wrong credential look the
   * same, and the message of the exception is not sent.
   *
   * @param ex the security exception
   * @return 401
   */
  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException ex) {
    return reject(HttpStatus.UNAUTHORIZED, AUTHENTICATION_REQUIRED, ex);
  }

  /**
   * Handles an authenticated caller that has no right to the resource.
   *
   * @param ex the security exception
   * @return 403
   */
  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex) {
    return reject(HttpStatus.FORBIDDEN, ACCESS_DENIED, ex);
  }

  /**
   * Handles a violation of a database constraint.
   *
   * <p>A race on a UNIQUE constraint of the table {@code credentials} is a client error (409),
   * recognized by the constraint name, which does not depend on the language of the server
   * messages. Any other violation is a bug: 500, and only the constraint name is logged, because
   * the message of the exception holds the whole failing row.
   *
   * @param ex the exception of Spring Data
   * @return 409 or 500
   */
  @ExceptionHandler(DataIntegrityViolationException.class)
  public ResponseEntity<ProblemDetail> handleDataIntegrityViolation(
      DataIntegrityViolationException ex) {
    String constraint = ViolatedConstraint.nameOf(ex);
    String detail = constraint == null ? null : UNIQUE_CONSTRAINT_DETAILS.get(constraint);
    if (detail != null) {
      return reject(HttpStatus.CONFLICT, detail, ex);
    }
    LOGGER.error("Unexpected integrity violation, constraint: {}", constraint);
    return internalServerError();
  }

  /**
   * Handles everything else: 500 with a generic detail, the stack trace goes to the log.
   *
   * @param ex any unexpected exception
   * @return 500
   */
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ProblemDetail> handleUnexpected(Exception ex) {
    LOGGER.error("Unexpected error", ex);
    return internalServerError();
  }

  /**
   * Handles a request body that fails validation: 400 with the extension {@code errors}, a list
   * of {@link FieldViolation} sorted by field and message. Rejected values are never included.
   */
  @Override
  protected ResponseEntity<Object> handleMethodArgumentNotValid(
      MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status,
      WebRequest request) {
    List<FieldViolation> errors = ex.getBindingResult().getFieldErrors().stream()
        .map(error -> new FieldViolation(error.getField(),
            Objects.requireNonNullElse(error.getDefaultMessage(), "is invalid")))
        .sorted(Comparator.comparing(FieldViolation::field)
            .thenComparing(FieldViolation::message))
        .toList();
    ProblemDetail problem =
        ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Request validation failed");
    problem.setProperty("errors", errors);
    LOGGER.info("Request rejected with {}: {} invalid field(s)", HttpStatus.BAD_REQUEST.value(),
        errors.size());
    return handleExceptionInternal(ex, problem, headers, status, request);
  }

  /** A rejection of the client: logged at INFO in one line, without a stack trace. */
  private static ResponseEntity<ProblemDetail> reject(HttpStatus status, String detail,
      Exception ex) {
    LOGGER.info("Request rejected with {}: {}", status.value(), ex.getClass().getSimpleName());
    return ResponseEntity.status(status).body(ProblemDetail.forStatusAndDetail(status, detail));
  }

  private static ResponseEntity<ProblemDetail> internalServerError() {
    ProblemDetail problem = ProblemDetail.forStatusAndDetail(
        HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
  }
}
