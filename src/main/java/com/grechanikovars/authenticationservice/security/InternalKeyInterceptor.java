package com.grechanikovars.authenticationservice.security;

import com.grechanikovars.authenticationservice.exception.InvalidInternalKeyException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Lets a request through only if it carries the internal key in the header
 * {@value #HEADER}.
 *
 * <p>The internal endpoints are called by other services (the Gateway) before the user has a
 * token, so a JWT cannot protect them. The shared key keeps any other caller out. The keys are
 * compared with {@link MessageDigest#isEqual(byte[], byte[])}, which takes the same time wherever
 * the first difference is, so the key cannot be guessed byte by byte from the response time.
 * A refusal is an {@link InvalidInternalKeyException}, which the error handler turns into 401.
 * The interceptor runs before the request body is read, so a wrong key is a 401 even for an
 * invalid body.
 */
public class InternalKeyInterceptor implements HandlerInterceptor {

  /** The name of the header that carries the key. */
  public static final String HEADER = "X-Internal-Key";

  private final byte[] expectedKey;

  /**
   * Creates the interceptor.
   *
   * @param apiKey the expected key
   * @throws IllegalArgumentException if the key is missing or blank: the application must not
   *     start with an open internal endpoint
   */
  public InternalKeyInterceptor(String apiKey) {
    if (apiKey == null || apiKey.isBlank()) {
      throw new IllegalArgumentException(
          "The internal key is not set: provide the environment variable INTERNAL_API_KEY");
    }
    this.expectedKey = apiKey.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
      Object handler) {
    String providedKey = request.getHeader(HEADER);
    if (providedKey == null
        || !MessageDigest.isEqual(expectedKey, providedKey.getBytes(StandardCharsets.UTF_8))) {
      throw new InvalidInternalKeyException();
    }
    return true;
  }
}
