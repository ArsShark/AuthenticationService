package com.grechanikovars.authenticationservice.security;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.grechanikovars.authenticationservice.exception.InvalidInternalKeyException;
import jakarta.servlet.FilterChain;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Unit tests of {@link InternalKeyAuthenticationFilter}: plain servlet mocks, no Spring context.
 * What the filter does to the security context is read from inside the filter chain, because
 * that is where the access rules would see it.
 */
@ExtendWith(MockitoExtension.class)
class InternalKeyAuthenticationFilterTest {

  private static final String KEY = "secret-key-123";
  private static final String INTERNAL_PATH = "/internal/credentials";

  @Mock
  private AuthenticationEntryPoint entryPoint;

  private final MockHttpServletResponse response = new MockHttpServletResponse();
  private final AtomicInteger chainCalls = new AtomicInteger();
  private final AtomicReference<Authentication> seenInChain = new AtomicReference<>();
  private final FilterChain chain = (request, response) -> {
    chainCalls.incrementAndGet();
    seenInChain.set(SecurityContextHolder.getContext().getAuthentication());
  };

  private InternalKeyAuthenticationFilter filter() {
    return new InternalKeyAuthenticationFilter(KEY, entryPoint);
  }

  private static MockHttpServletRequest request(String path, String key) {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
    if (key != null) {
      request.addHeader(InternalKeyAuthenticationFilter.HEADER, key);
    }
    return request;
  }

  @AfterEach
  void clearTheSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void theRightKeyAuthenticatesAnInternalCallerAndTheRequestContinues() throws Exception {
    filter().doFilter(request(INTERNAL_PATH, KEY), response, chain);

    Authentication authentication = seenInChain.get();
    assertNotNull(authentication);
    List<String> authorities = authentication.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority).toList();
    assertAll(
        () -> assertEquals(1, chainCalls.get()),
        () -> assertTrue(authentication.isAuthenticated()),
        () -> assertEquals("internal-service", authentication.getName()),
        () -> assertEquals(List.of("ROLE_INTERNAL"), authorities));
    verifyNoInteractions(entryPoint);
  }

  @Test
  void aRequestWithoutTheHeaderStaysAnonymousAndContinues() throws Exception {
    filter().doFilter(request(INTERNAL_PATH, null), response, chain);

    assertAll(
        () -> assertEquals(1, chainCalls.get()),
        () -> assertNull(seenInChain.get()));
    verifyNoInteractions(entryPoint);
  }

  /** Empty, different, a prefix of the key, the key plus a character, the key in other case. */
  @ParameterizedTest
  @ValueSource(strings = {"", "wrong-key", "secret-key-12", "secret-key-1234", "SECRET-KEY-123"})
  void aWrongKeyStopsTheRequestAtTheEntryPoint(String providedKey) throws Exception {
    MockHttpServletRequest request = request(INTERNAL_PATH, providedKey);

    filter().doFilter(request, response, chain);

    ArgumentCaptor<InvalidInternalKeyException> exception =
        ArgumentCaptor.forClass(InvalidInternalKeyException.class);
    verify(entryPoint).commence(any(), any(), exception.capture());
    assertAll(
        () -> assertNotNull(exception.getValue()),
        () -> assertEquals(0, chainCalls.get()),
        () -> assertNull(SecurityContextHolder.getContext().getAuthentication()));
  }

  /** The key has a meaning only under /internal: nowhere else it authenticates anyone. */
  @Test
  void theRightKeyOutsideTheInternalPathIsIgnored() throws Exception {
    filter().doFilter(request("/api/auth/credentials", KEY), response, chain);

    assertAll(
        () -> assertEquals(1, chainCalls.get()),
        () -> assertNull(seenInChain.get()));
    verifyNoInteractions(entryPoint);
  }

  /** Outside /internal the filter does not even reject: the access rules answer there. */
  @Test
  void aWrongKeyOutsideTheInternalPathIsIgnored() throws Exception {
    filter().doFilter(request("/api/auth/credentials", "wrong-key"), response, chain);

    assertAll(
        () -> assertEquals(1, chainCalls.get()),
        () -> assertNull(seenInChain.get()));
    verifyNoInteractions(entryPoint);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void missingOrBlankKeyIsRejectedAtCreation(String apiKey) {
    assertThrows(IllegalArgumentException.class,
        () -> new InternalKeyAuthenticationFilter(apiKey, entryPoint));
  }
}
