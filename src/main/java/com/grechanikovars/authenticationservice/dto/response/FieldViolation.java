package com.grechanikovars.authenticationservice.dto.response;

/**
 * One failed validation rule of a request: the field and a message that never holds the rejected
 * value.
 *
 * @param field the name of the field in the request body
 * @param message what is wrong with the field
 */
public record FieldViolation(String field, String message) {
}
