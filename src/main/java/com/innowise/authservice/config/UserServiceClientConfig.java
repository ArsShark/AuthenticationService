package com.innowise.authservice.config;

import java.net.http.HttpClient;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Builds the {@link RestClient} that calls the internal endpoints of the User Service.
 *
 * <p>The client always sends the internal key in the header {@code X-Internal-Key}; the User
 * Service accepts the calls of {@code /internal/**} only with it. Both timeouts are set: a
 * registration must not hang on a service that does not answer.
 */
@Configuration
@EnableConfigurationProperties(UserServiceProperties.class)
public class UserServiceClientConfig {

  /** The header with the shared key of the internal endpoints. */
  public static final String INTERNAL_KEY_HEADER = "X-Internal-Key";

  /**
   * Creates the client of the User Service.
   *
   * <p>HTTP/1.1 is forced: the JDK client would first try to upgrade a plain HTTP connection to
   * HTTP/2, which some servers answer badly.
   *
   * @param properties the address and the timeouts
   * @param internal the shared key of the internal endpoints
   * @return a client with the base address, the key and the timeouts set
   */
  @Bean
  public RestClient userServiceRestClient(UserServiceProperties properties,
      InternalApiProperties internal) {
    HttpClient httpClient = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_1_1)
        .connectTimeout(properties.connectTimeout())
        .build();
    JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
    requestFactory.setReadTimeout(properties.readTimeout());
    return RestClient.builder()
        .baseUrl(properties.baseUri())
        .requestFactory(requestFactory)
        .defaultHeader(INTERNAL_KEY_HEADER, internal.apiKey())
        .build();
  }
}
