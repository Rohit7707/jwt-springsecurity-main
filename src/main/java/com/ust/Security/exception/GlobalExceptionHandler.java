package com.ust.Security.exception;

import jakarta.validation.ConstraintViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<String> handleValidationException(ConstraintViolationException ex) {
        ex.getConstraintViolations().forEach(violation -> {
            System.out.println("Validation error: " + violation.getMessage());
        });
        return ResponseEntity.badRequest().body("Validation error: " + ex.getMessage());
    }
}

