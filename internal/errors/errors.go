// Package errors provides structured error types with codes for the IdP.
package errors

import (
	"errors"
	"fmt"
)

// Error codes for categorizing errors.
const (
	CodeInternal       = "internal_error"
	CodeNotFound       = "not_found"
	CodeAlreadyExists  = "already_exists"
	CodeInvalidInput   = "invalid_input"
	CodeUnauthorized   = "unauthorized"
	CodeForbidden      = "forbidden"
	CodeRateLimited    = "rate_limited"
	CodeTokenExpired   = "token_expired"
	CodeTokenInvalid   = "token_invalid"
	CodeSessionExpired = "session_expired"
)

// Error represents a structured error with a code and message.
type Error struct {
	Code    string
	Message string
	Err     error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Err
}

// New creates a new Error with the given code and message.
func New(code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// Wrap wraps an existing error with a code and message.
func Wrap(err error, code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// IsCode checks if an error has a specific error code.
func IsCode(err error, code string) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Code == code
	}
	return false
}

// NotFound creates a not found error.
func NotFound(resource, id string) *Error {
	return &Error{
		Code:    CodeNotFound,
		Message: fmt.Sprintf("%s not found: %s", resource, id),
	}
}

// AlreadyExists creates an already exists error.
func AlreadyExists(resource, id string) *Error {
	return &Error{
		Code:    CodeAlreadyExists,
		Message: fmt.Sprintf("%s already exists: %s", resource, id),
	}
}

// InvalidInput creates an invalid input error.
func InvalidInput(message string) *Error {
	return &Error{
		Code:    CodeInvalidInput,
		Message: message,
	}
}

// Unauthorized creates an unauthorized error.
func Unauthorized(message string) *Error {
	return &Error{
		Code:    CodeUnauthorized,
		Message: message,
	}
}

// Internal creates an internal error.
func Internal(message string, err error) *Error {
	return &Error{
		Code:    CodeInternal,
		Message: message,
		Err:     err,
	}
}
