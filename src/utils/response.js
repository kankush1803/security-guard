'use strict';

const { SecurityError } = require('./errors');

/**
 * Send a standardized security rejection response.
 *
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {SecurityError|Error|string} error - The error or message to respond with.
 * @param {number} [statusCode] - Optional status code override.
 * @param {Function} [customHandler] - Optional custom rejection handler (req, res, error).
 */
function sendSecurityResponse(req, res, error, statusCode, customHandler) {
  if (res.headersSent) {
    return;
  }

  if (typeof customHandler === 'function') {
    return customHandler(req, res, error);
  }

  let status = statusCode;
  let code = 'SECURITY_ERROR';
  let message = 'Access denied by security policy.';
  let details = null;

  if (error instanceof SecurityError) {
    status = status || error.statusCode;
    code = error.code;
    message = error.message;
    details = error.details;
  } else if (error instanceof Error) {
    status = status || 500;
    message = error.message;
  } else if (typeof error === 'string') {
    status = status || 400;
    message = error;
  }

  status = status || 403;

  const payload = {
    success: false,
    error: {
      code,
      message,
      ...(details ? { details } : {})
    }
  };

  res.status(status).json(payload);
}

module.exports = {
  sendSecurityResponse
};

