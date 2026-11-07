'use strict';

const crypto = require('crypto');

/**
 * List of sensitive key substrings or names that must always be redacted.
 */
const DEFAULT_SENSITIVE_KEYS = [
  'password',
  'pass',
  'secret',
  'token',
  'api_key',
  'apikey',
  'authorization',
  'bearer',
  'auth',
  'cookie',
  'set-cookie',
  'access_token',
  'refresh_token',
  'private_key',
  'session_id',
  'credit_card',
  'card_number',
  'cvv',
  'ssn'
];

/**
 * Redact sensitive fields from any data structure.
 * Handles objects, arrays, circular references, and string representations.
 *
 * @param {any} value - Value to redact.
 * @param {string[]} [customSensitiveKeys] - Additional keys to redact.
 * @param {Set<any>} [seen] - Visited objects to prevent cyclic recursion.
 * @returns {any} Redacted data.
 */
function redact(value, customSensitiveKeys = [], seen = new Set()) {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value !== 'object') {
    return value;
  }

  if (seen.has(value)) {
    return '[Circular]';
  }
  seen.add(value);

  const sensitiveKeys = [...DEFAULT_SENSITIVE_KEYS, ...customSensitiveKeys].map((k) => k.toLowerCase());

  if (Array.isArray(value)) {
    return value.map((item) => redact(item, customSensitiveKeys, seen));
  }

  const result = {};
  for (const [key, val] of Object.entries(value)) {
    const lowerKey = key.toLowerCase();
    const isSensitive = sensitiveKeys.some((s) => lowerKey.includes(s));

    if (typeof val === 'object' && val !== null) {
      // Recurse into nested objects and arrays so child properties are inspected and redacted
      result[key] = redact(val, customSensitiveKeys, seen);
    } else if (isSensitive) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = val;
    }
  }

  return result;
}

/**
 * Retrieve or generate a unique request identifier.
 *
 * @param {import('express').Request} req - Express request object.
 * @returns {string} Request ID.
 */
function getRequestId(req) {
  if (!req) {
    return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  }

  if (req.id && typeof req.id === 'string') {
    return req.id;
  }

  const headerId = req.headers && (req.headers['x-request-id'] || req.headers['x-correlation-id']);
  if (headerId && typeof headerId === 'string') {
    return headerId;
  }

  const generated = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  req.id = generated;
  return generated;
}

/**
 * Security Logger wrapper.
 */
class SecurityLogger {
  /**
   * @param {Object} [options]
   * @param {boolean} [options.enabled=true]
   * @param {'info'|'warn'|'error'|'debug'|'silent'} [options.level='warn']
   * @param {Function} [options.customLogger] - Custom logger callback (event => void)
   * @param {string[]} [options.redactFields=[]] - Custom fields to redact
   */
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.level = options.level || 'warn';
    this.customLogger = typeof options.customLogger === 'function' ? options.customLogger : null;
    this.redactFields = Array.isArray(options.redactFields) ? options.redactFields : [];

    this.levelWeights = {
      debug: 10,
      info: 20,
      warn: 30,
      error: 40,
      silent: 99
    };
  }

  /**
   * Check if a log level is enabled.
   * @param {'debug'|'info'|'warn'|'error'} level
   * @returns {boolean}
   */
  shouldLog(level) {
    if (!this.enabled || this.level === 'silent') {
      return false;
    }
    const currentWeight = this.levelWeights[this.level] || 30;
    const targetWeight = this.levelWeights[level] || 30;
    return targetWeight >= currentWeight;
  }

  /**
   * Log a security event.
   *
   * @param {'debug'|'info'|'warn'|'error'} level - Log severity level.
   * @param {string} eventType - Type of security event (e.g. 'RATE_LIMIT_EXCEEDED', 'API_KEY_AUTH_FAILED').
   * @param {string} message - Descriptive event message.
   * @param {Object} [context] - Context data (req, ip, details).
   */
  log(level, eventType, message, context = {}) {
    if (!this.shouldLog(level)) {
      return;
    }

    const req = context.req;
    const reqId = getRequestId(req);

    const event = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      eventType,
      message,
      requestId: reqId,
      ip: context.ip || (req && (req.ip || req.socket?.remoteAddress)) || 'unknown',
      method: req ? req.method : undefined,
      path: req ? (req.originalUrl || req.url) : undefined,
      details: redact(context.details || {}, this.redactFields)
    };

    // Remove undefined fields
    Object.keys(event).forEach((k) => event[k] === undefined && delete event[k]);

    if (this.customLogger) {
      try {
        this.customLogger(event);
      } catch (err) {
        // Fallback to console.error if custom logger throws
        console.error('[secure-api-guard] Custom logger error:', err.message);
      }
      return;
    }

    const formatted = `[secure-api-guard] [${event.timestamp}] [${event.level}] [${event.eventType}] ${event.message} (reqId=${event.requestId}, ip=${event.ip})`;

    const logFn = typeof console[level] === 'function' ? console[level] : console.log;
    logFn(formatted, event.details);
  }

  debug(eventType, message, context) {
    this.log('debug', eventType, message, context);
  }

  info(eventType, message, context) {
    this.log('info', eventType, message, context);
  }

  warn(eventType, message, context) {
    this.log('warn', eventType, message, context);
  }

  error(eventType, message, context) {
    this.log('error', eventType, message, context);
  }
}

// Default singleton logger instance with silent/warn behavior
const defaultLogger = new SecurityLogger({ level: 'warn' });

module.exports = {
  SecurityLogger,
  defaultLogger,
  redact,
  getRequestId,
  DEFAULT_SENSITIVE_KEYS
};
