'use strict';

/**
 * Base security error class.
 */
class SecurityError extends Error {
  /**
   * @param {string} message - Human-readable error message.
   * @param {number} [statusCode=500] - HTTP status code.
   * @param {string} [code='SECURITY_ERROR'] - Machine-readable error code.
   * @param {Record<string, any>} [details=null] - Optional structured error details.
   */
  constructor(message, statusCode = 500, code = 'SECURITY_ERROR', details = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  toJSON() {
    return {
      success: false,
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {})
      }
    };
  }
}

class RateLimitError extends SecurityError {
  constructor(message = 'Too many requests, please try again later.', details = null) {
    super(message, 429, 'RATE_LIMIT_EXCEEDED', details);
  }
}

class AuthenticationError extends SecurityError {
  constructor(message = 'Unauthorized: Invalid or missing API key.', details = null) {
    super(message, 401, 'UNAUTHORIZED', details);
  }
}

class ForbiddenError extends SecurityError {
  constructor(message = 'Forbidden: Access denied.', details = null) {
    super(message, 403, 'FORBIDDEN', details);
  }
}

class PayloadTooLargeError extends SecurityError {
  constructor(message = 'Payload Too Large: Request body exceeds maximum allowed size.', details = null) {
    super(message, 413, 'PAYLOAD_TOO_LARGE', details);
  }
}

class ValidationError extends SecurityError {
  constructor(message = 'Validation failed: Invalid request parameters.', details = null) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

class ThreatDetectedError extends SecurityError {
  constructor(message = 'Forbidden: Suspicious request pattern detected.', statusCode = 403, details = null) {
    super(message, statusCode, 'THREAT_DETECTED', details);
  }
}

class ConfigurationError extends SecurityError {
  constructor(message, details = null) {
    super(message, 500, 'CONFIGURATION_ERROR', details);
  }
}

module.exports = {
  SecurityError,
  RateLimitError,
  AuthenticationError,
  ForbiddenError,
  PayloadTooLargeError,
  ValidationError,
  ThreatDetectedError,
  ConfigurationError
};

