package com.grechanikovars.authenticationservice.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

/**
 * Tests {@link ProblemDetailSecurityHandler}: the exception goes to the resolver of Spring MVC
 * with no handler, and when nobody answers, the response still gets an error status. The format
 * of the body is tested with the real resolver in {@code SecurityConfigTest}.
 */
@ExtendWith(MockitoExtension.class)
class ProblemDetailSecurityHandlerTest {

  @Mock
  private HandlerExceptionResolver resolver;

  private ProblemDetailSecurityHandler handler;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;

  @BeforeEach
  void setUp() {
    handler = new ProblemDetailSecurityHandler(resolver);
    request = new MockHttpServletRequest();
    response = new MockHttpServletResponse();
  }

  @Test
  void anAuthenticationFailureGoesToTheResolverWithoutAHandler() {
    AuthenticationException exception = new InsufficientAuthenticationException("any");
    when(resolver.resolveException(request, response, null, exception))
        .thenReturn(new ModelAndView());

    handler.commence(request, response, exception);

    verify(resolver).resolveException(request, response, null, exception);
    // The resolver writes the answer; the handler must not add a status of its own.
    assertEquals(200, response.getStatus());
  }

  @Test
  void anAccessDeniedGoesToTheResolverWithoutAHandler() {
    AccessDeniedException exception = new AccessDeniedException("any");
    when(resolver.resolveException(request, response, null, exception))
        .thenReturn(new ModelAndView());

    handler.handle(request, response, exception);

    verify(resolver).resolveException(request, response, null, exception);
    assertEquals(200, response.getStatus());
  }

  @Test
  void unauthorizedIsSentWhenNobodyAnswersAnAuthenticationFailure() {
    AuthenticationException exception = new InsufficientAuthenticationException("any");
    when(resolver.resolveException(request, response, null, exception)).thenReturn(null);

    handler.commence(request, response, exception);

    assertEquals(401, response.getStatus());
  }

  @Test
  void forbiddenIsSentWhenNobodyAnswersAnAccessDenied() {
    AccessDeniedException exception = new AccessDeniedException("any");
    when(resolver.resolveException(request, response, null, exception)).thenReturn(null);

    handler.handle(request, response, exception);

    assertEquals(403, response.getStatus());
  }
}
