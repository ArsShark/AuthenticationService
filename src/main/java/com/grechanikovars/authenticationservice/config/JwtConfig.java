package com.grechanikovars.authenticationservice.config;

import com.grechanikovars.authenticationservice.security.JwtKeys;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * Creates the signing key and the encoder and the decoder of the tokens.
 *
 * <p>The beans are created as plain method calls too ({@code new JwtConfig().jwtEncoder(keys)}),
 * so unit tests can build the very same encoder and decoder without a Spring context.
 *
 * <p>This service is not a resource server: no filter reads a bearer token here. The decoder is
 * used only by the token service, to read the tokens that the service itself issued.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {

  /**
   * Reads the private key and derives the public key and the key id from it.
   *
   * @param properties the token settings
   * @return the key pair; the application does not start if the key is missing or invalid
   */
  @Bean
  public JwtKeys jwtKeys(JwtProperties properties) {
    return JwtKeys.fromPkcs8Base64(properties.privateKey());
  }

  /**
   * Creates the encoder that signs tokens with RS256.
   *
   * <p>The header of every token carries {@code alg=RS256}, {@code typ=JWT} and the {@code kid}
   * of the key. The encoder does not look at the time: the caller sets {@code iat} and
   * {@code exp} from the application clock.
   *
   * @param keys the key pair
   * @return the encoder
   */
  @Bean
  public JwtEncoder jwtEncoder(JwtKeys keys) {
    return NimbusJwtEncoder.withKeyPair(keys.publicKey(), keys.privateKey())
        .jwkPostProcessor(jwk -> jwk.keyID(keys.keyId()))
        .build();
  }

  /**
   * Creates the decoder that verifies the signature (RS256 only), the issuer and the time.
   *
   * <p>The time comes from the application {@link Clock}, not from the system clock, and there is
   * no clock skew: the default of {@link JwtTimestampValidator} is 60 seconds, which would keep an
   * expired token alive for another minute. A token without an {@code exp} claim is rejected. The
   * claim {@code token_type} is not checked here; the token service checks it, because it depends
   * on the endpoint which type is expected.
   *
   * @param keys the key pair; only the public key is used
   * @param properties the token settings; the expected issuer
   * @param clock the application clock
   * @return the decoder
   */
  @Bean
  public JwtDecoder jwtDecoder(JwtKeys keys, JwtProperties properties, Clock clock) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keys.publicKey())
        .signatureAlgorithm(SignatureAlgorithm.RS256)
        .build();
    JwtTimestampValidator timestampValidator = new JwtTimestampValidator(Duration.ZERO);
    timestampValidator.setClock(clock);
    timestampValidator.setAllowEmptyExpiryClaim(false);
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<Jwt>(
        List.<OAuth2TokenValidator<Jwt>>of(
            timestampValidator, new JwtIssuerValidator(properties.issuer()))));
    return decoder;
  }
}
