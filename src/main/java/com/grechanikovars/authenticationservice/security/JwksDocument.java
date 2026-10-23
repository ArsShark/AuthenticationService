package com.grechanikovars.authenticationservice.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.Map;

/**
 * The JSON Web Key Set (RFC 7517) that publishes the public key of the service.
 *
 * <p>Other services read it to verify the tokens that this service signs: the Gateway and the
 * User Service fetch it from the internal address of this service and cache it. It holds one key
 * with the members {@code kty}, {@code use}, {@code alg}, {@code kid}, {@code n} and {@code e},
 * and never a private one. The {@code kid} is the same as in the header of every token, so a
 * client finds the key by it.
 *
 * <p>The document is built once, when the application starts, because the key does not change
 * while the application runs.
 *
 * @param jwkSet the JSON object of the set, as a map: {@code {"keys": [ { ... } ]}}; it cannot be
 *     changed
 */
public record JwksDocument(Map<String, Object> jwkSet) {

  public JwksDocument {
    jwkSet = Map.copyOf(jwkSet);
  }

  /**
   * Builds the document from the key pair of the service.
   *
   * @param keys the key pair; only the public key and the key id are used
   * @return the set with the public key, marked for signature verification with RS256
   */
  public static JwksDocument from(JwtKeys keys) {
    RSAKey publicKey = new RSAKey.Builder(keys.publicKey())
        .keyUse(KeyUse.SIGNATURE)
        .algorithm(JWSAlgorithm.RS256)
        .keyID(keys.keyId())
        .build();
    return new JwksDocument(new JWKSet(publicKey).toJSONObject(true));
  }
}
