package com.innowise.authservice.mapper;

import com.innowise.authservice.dto.response.TokenResponse;
import com.innowise.authservice.service.IssuedToken;
import com.innowise.authservice.service.TokenPair;
import java.time.Duration;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;

/**
 * Turns a freshly issued pair of tokens into the answer of a login or a refresh.
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface TokenMapper {

  /**
   * Builds the answer from a freshly issued pair.
   *
   * @param pair the access token and the refresh token
   * @return the response; the lifetime is the distance between the issue and the expiry of the
   *     access token
   */
  @Mapping(target = "accessToken", source = "access.value")
  @Mapping(target = "refreshToken", source = "refresh.value")
  @Mapping(target = "tokenType", constant = TokenResponse.BEARER)
  @Mapping(target = "expiresIn", source = "access", qualifiedByName = "lifetimeInSeconds")
  TokenResponse toResponse(TokenPair pair);

  /**
   * Counts the seconds a token lives.
   *
   * @param token an issued token
   * @return the seconds between the issue and the expiry
   */
  @Named("lifetimeInSeconds")
  default long lifetimeInSeconds(IssuedToken token) {
    return Duration.between(token.issuedAt(), token.expiresAt()).toSeconds();
  }
}
