package com.grechanikovars.authenticationservice.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Checks {@link ValidPassword} by asking {@link PasswordPolicy}.
 */
public class ValidPasswordValidator implements ConstraintValidator<ValidPassword, String> {

  @Override
  public boolean isValid(String value, ConstraintValidatorContext context) {
    return value == null || PasswordPolicy.isValid(value);
  }
}
