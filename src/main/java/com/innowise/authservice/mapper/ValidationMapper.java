package com.innowise.authservice.mapper;

import com.innowise.authservice.dto.response.ValidationResponse;
import com.innowise.authservice.service.AccessTokenClaims;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

/**
 * Turns the claims of a valid access token into the answer of the validation.
 *
 * <p>The email and the id of the account are in the claims but never in the answer. A token that
 * is not valid has no claims; its answer is {@link ValidationResponse#invalid()}.
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface ValidationMapper {

  /**
   * Describes a valid token.
   *
   * @param claims the claims of a token that passed every check
   * @return the answer with the user, the role and the expiry
   */
  @Mapping(target = "valid", constant = "true")
  ValidationResponse toResponse(AccessTokenClaims claims);
}
