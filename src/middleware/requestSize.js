'use strict';

const bytes = require('bytes');
const defaults = require('../config/defaults');
const { validateRequestSizeConfig } = require('../config/validateConfig');
const { PayloadTooLargeError, SecurityError } = require('../utils/errors');
const { sendSecurityResponse } = require('../utils/response');
const { defaultLogger } = require('../utils/logger');

/**
 * Parses and validates Content-Length header against HTTP smuggling / desync attacks.
 *
 * @param {import('express').Request} req
 * @returns {{ length: number | null, error: string | null }}
 */
function parseContentLength(req) {
  const rawHeader = req.headers && req.headers['content-length'];

  if (rawHeader === undefined || rawHeader === null || rawHeader === '') {
    return { length: null, error: null };
  }

  // Handle array of headers or comma-separated multiple values
  const values = Array.isArray(rawHeader)
    ? rawHeader
    : String(rawHeader).split(',').map((v) => v.trim());

  // Check for differing values in multiple headers (HTTP request smuggling risk)
  const uniqueValues = new Set(values);
  if (uniqueValues.size > 1) {
    return {
      length: null,
      error: 'Conflicting Content-Length headers detected (possible HTTP smuggling).'
    };
  }

  const lengthStr = values[0];
  if (!/^\d+$/.test(lengthStr)) {
    return {
      length: null,
      error: 'Malformed Content-Length header: must be a non-negative integer.'
    };
  }

  const parsed = parseInt(lengthStr, 10);
  return { length: parsed, error: null };
}

/**
 * Creates request size limiting middleware.
 *
 * @param {Object} [userOptions]
 * @param {string|number} [userOptions.maxSize='1mb'] - Max size in bytes or string ('1mb', '500kb').
 * @param {number} [userOptions.statusCode=413] - HTTP status code on limit exceed.
 * @param {string} [userOptions.message] - Custom error message.
 * @param {Function} [userOptions.handler] - Custom response handler.
 * @param {import('../utils/logger').SecurityLogger} [userOptions.logger] - Logger instance.
 * @returns {import('express').RequestHandler}
 */
function createRequestSize(userOptions = {}) {
  validateRequestSizeConfig(userOptions);

  const options = {
    ...defaults.requestSize,
    ...userOptions
  };

  const maxBytes = typeof options.maxSize === 'number'
    ? options.maxSize
    : bytes.parse(options.maxSize) || 1048576; // default 1MB

  const logger = options.logger || defaultLogger;

  return function requestSizeMiddleware(req, res, next) {
    // 1. Inspect Content-Length header
    const { length: contentLength, error: headerError } = parseContentLength(req);

    if (headerError) {
      logger.warn('REQUEST_SIZE_HEADER_INVALID', headerError, { req });
      const secError = new SecurityError(headerError, 400, 'BAD_REQUEST');
      return sendSecurityResponse(req, res, secError, 400, options.handler);
    }

    if (contentLength !== null && contentLength > maxBytes) {
      logger.warn('REQUEST_SIZE_EXCEEDED', `Content-Length (${contentLength}) exceeds limit (${maxBytes})`, {
        req,
        details: { contentLength, maxBytes }
      });
      res.setHeader('Connection', 'close');
      const error = new PayloadTooLargeError(options.message, { contentLength, maxBytes });
      return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
    }

    // 2. Check if body is already parsed by upstream body parser
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      try {
        let estimatedSize = 0;
        if (Buffer.isBuffer(req.body)) {
          estimatedSize = req.body.length;
        } else {
          estimatedSize = Buffer.byteLength(JSON.stringify(req.body), 'utf8');
        }

        if (estimatedSize > maxBytes) {
          logger.warn('REQUEST_SIZE_EXCEEDED', `Parsed body size (${estimatedSize}) exceeds limit (${maxBytes})`, {
            req,
            details: { estimatedSize, maxBytes }
          });
          const error = new PayloadTooLargeError(options.message, { estimatedSize, maxBytes });
          return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
        }
      } catch {
        // Ignore serialization failure; proceed to streaming check
      }
    }

    // 3. For unparsed streams or chunked transfer-encoding, monitor incoming chunks safely
    let receivedBytes = 0;
    let rejected = false;

    const originalEmit = req.emit;
    if (typeof originalEmit === 'function') {
      req.emit = function (eventName, ...args) {
        if (eventName === 'data' && !rejected) {
          const chunk = args[0];
          if (chunk) {
            receivedBytes += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
            if (receivedBytes > maxBytes) {
              rejected = true;
              if (typeof req.pause === 'function') {
                req.pause();
              }
              logger.warn('REQUEST_SIZE_EXCEEDED', `Streamed body (${receivedBytes}) exceeded limit (${maxBytes})`, {
                req,
                details: { receivedBytes, maxBytes }
              });

              res.setHeader('Connection', 'close');
              const error = new PayloadTooLargeError(options.message, { receivedBytes, maxBytes });
              sendSecurityResponse(req, res, error, options.statusCode, options.handler);
              return false;
            }
          }
        }
        return originalEmit.apply(this, [eventName, ...args]);
      };
    }

    return next();
  };
}

module.exports = {
  requestSize: createRequestSize,
  createRequestSize,
  parseContentLength
};
