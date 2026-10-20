package com.grechanikovars.authenticationservice.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a raw password that must follow {@link PasswordPolicy}.
 *
 * <p>A {@code null} value is valid for this constraint; combine it with {@code @NotNull}.
 */
@Documented
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = ValidPasswordValidator.class)
public @interface ValidPassword {

  String message() default
      "must not be blank, must have at least 8 characters and at most 72 bytes in UTF-8";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
