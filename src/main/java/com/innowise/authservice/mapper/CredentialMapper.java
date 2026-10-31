package com.innowise.authservice.mapper;

import com.innowise.authservice.dto.response.CredentialResponse;
import com.innowise.authservice.entity.Credential;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

/**
 * Turns an account into its public view.
 *
 * <p>{@link CredentialResponse} has no password hash. The target has no such component, so the
 * hash cannot be copied by mistake; {@code unmappedTargetPolicy = ERROR} also makes a new
 * component of the response a compile error until it is mapped on purpose.
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.ERROR)
public interface CredentialMapper {

  /**
   * Describes a saved account.
   *
   * @param credential a saved account
   * @return the public view of the account; the response calls the username {@code login}
   */
  @Mapping(target = "login", source = "username")
  CredentialResponse toResponse(Credential credential);
}
