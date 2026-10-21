package com.grechanikovars.authenticationservice.security;

import com.grechanikovars.authenticationservice.exception.InvalidInternalKeyException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Objects;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates a call to an internal endpoint by the internal key in the header
 * {@value #HEADER}.
 *
 * <p>The internal endpoints are called by other services (the Gateway) before the user has a
 * token, so a JWT cannot protect them. The shared key keeps any other caller out. A call with
 * the right key becomes an authenticated caller with the role {@value #ROLE}; the rule
 * {@code /internal/** -> hasRole('INTERNAL')} of the security chain lets only that caller in.
 *
 * <ul>
 *   <li>The filter acts only on {@code /internal/**}. Elsewhere the header means nothing, so a
 *       key sent to any other path never authenticates anyone.</li>
 *   <li>No header: the request stays anonymous and the access rules answer 401, as for any other
 *       missing credential.</li>
 *   <li>A wrong key: the filter stops the request at once and asks the entry point for the 401,
 *       as the filters of HTTP Basic and Bearer tokens do. The answer is the same as for a
 *       missing key.</li>
 * </ul>
 *
 * <p>The keys are compared with {@link MessageDigest#isEqual(byte[], byte[])}, which takes the
 * same time wherever the first difference is, so the key cannot be guessed byte by byte from the
 * response time. The filter runs before the request body is read, so a wrong key is a 401 even
 * for an invalid body.
 *
 * <p>This class must not be a Spring bean: Spring Boot would register every {@code Filter} bean
 * in the servlet filter chain as well, outside the security chain. The security chain creates it.
 */
public class InternalKeyAuthenticationFilter extends OncePerRequestFilter {

  /** The name of the header that carries the key. */
  public static final String HEADER = "X-Internal-Key";

  /** The role of an authenticated internal caller, as {@code hasRole} expects it. */
  public static final String ROLE = "INTERNAL";

  private static final String AUTHORITY = String.format("ROLE_%s", ROLE);
  private static final String PRINCIPAL = "internal-service";
  private static final RequestMatcher INTERNAL_PATH =
      PathPatternRequestMatcher.withDefaults().matcher("/internal/**");

  private final byte[] expectedKey;
  private final AuthenticationEntryPoint entryPoint;

  /**
   * Creates the filter.
   *
   * @param apiKey the expected key
   * @param entryPoint answers a request with a wrong key
   * @throws IllegalArgumentException if the key is missing or blank: the application must not
   *     start with an open internal endpoint
   */
  public InternalKeyAuthenticationFilter(String apiKey, AuthenticationEntryPoint entryPoint) {
    if (apiKey == null || apiKey.isBlank()) {
      throw new IllegalArgumentException(
          "The internal key is not set: provide the environment variable INTERNAL_API_KEY");
    }
    this.expectedKey = apiKey.getBytes(StandardCharsets.UTF_8);
    this.entryPoint = Objects.requireNonNull(entryPoint, "entryPoint");
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !INTERNAL_PATH.matches(request);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws ServletException, IOException {
    String providedKey = request.getHeader(HEADER);
    if (providedKey == null) {
      chain.doFilter(request, response);
      return;
    }
    if (!MessageDigest.isEqual(expectedKey, providedKey.getBytes(StandardCharsets.UTF_8))) {
      entryPoint.commence(request, response, new InvalidInternalKeyException());
      return;
    }
    SecurityContext context =
        SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
    context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
        PRINCIPAL, null, AuthorityUtils.createAuthorityList(AUTHORITY)));
    SecurityContextHolder.getContextHolderStrategy().setContext(context);
    chain.doFilter(request, response);
  }
}
