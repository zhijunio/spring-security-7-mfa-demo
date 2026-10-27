package com.example.springsecuritymfa.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
class SecurityProblemAdvice {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    ProblemDetail invalidRequest(MethodArgumentNotValidException ignored) {
        return problem(HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail invalidProof(IllegalArgumentException ignored) {
        return problem(HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalStateException.class)
    ProblemDetail unavailable(IllegalStateException ignored) {
        return problem(HttpStatus.CONFLICT);
    }

    private ProblemDetail problem(HttpStatus status) {
        return ProblemDetail.forStatusAndDetail(status, "Invalid, expired, or unavailable security operation");
    }
}
