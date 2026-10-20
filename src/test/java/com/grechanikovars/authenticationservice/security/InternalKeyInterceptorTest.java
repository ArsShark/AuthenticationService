package com.grechanikovars.authenticationservice.security;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.grechanikovars.authenticationservice.exception.InvalidInternalKeyException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Unit tests of {@link InternalKeyInterceptor}: plain servlet mocks, no Spring context.
 */
class InternalKeyInterceptorTest {

  private static final String KEY = "secret-key-123";

  private final InternalKeyInterceptor interceptor = new InternalKeyInterceptor(KEY);
  private final MockHttpServletResponse response = new MockHttpServletResponse();

  @Test
  void requestWithTheRightKeyPasses() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader(InternalKeyInterceptor.HEADER, KEY);

    assertTrue(interceptor.preHandle(request, response, new Object()));
  }

  @Test
  void requestWithoutTheHeaderIsRefused() {
    MockHttpServletRequest request = new MockHttpServletRequest();

    assertThrows(InvalidInternalKeyException.class,
        () -> interceptor.preHandle(request, response, new Object()));
  }

  /** Empty, different, a prefix of the key, the key plus a character, the key in other case. */
  @ParameterizedTest
  @ValueSource(strings = {"", "wrong-key", "secret-key-12", "secret-key-1234", "SECRET-KEY-123"})
  void requestWithAWrongKeyIsRefused(String providedKey) {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader(InternalKeyInterceptor.HEADER, providedKey);

    assertThrows(InvalidInternalKeyException.class,
        () -> interceptor.preHandle(request, response, new Object()));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void missingOrBlankKeyIsRejectedAtCreation(String apiKey) {
    assertThrows(IllegalArgumentException.class, () -> new InternalKeyInterceptor(apiKey));
  }
}
