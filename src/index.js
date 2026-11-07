'use strict';

// Middlewares
const { rateLimiter, createRateLimiter, defaultKeyGenerator } = require('./middleware/rateLimiter');
const { apiKeyAuth, createApiKeyAuth, extractApiKey } = require('./middleware/apiKeyAuth');
const { ipFilter, createIpFilter } = require('./middleware/ipFilter');
const { requestSize, createRequestSize, parseContentLength } = require('./middleware/requestSize');
const { securityHeaders, createSecurityHeaders } = require('./middleware/securityHeaders');
const { requestValidator, createRequestValidator, formatIssues } = require('./middleware/requestValidator');
const { threatDetector, createThreatDetector } = require('./middleware/threatDetector');

// Security Utilities
const {
  hashApiKey,
  generateApiKey,
  secureCompare,
  isKeyExpired
} = require('./security/apiKey');

const {
  parseIp,
  formatIp,
  parseRule,
  matchesRule,
  isIpInRules,
  compileRules,
  getClientIp
} = require('./security/ipAddress');

const {
  DEFAULT_THREAT_PATTERNS,
  scanValue
} = require('./security/detector');

// Stores
const { MemoryStore } = require('./stores/memoryStore');
const { RedisStore } = require('./stores/redisStore');

// Configuration
const defaults = require('./config/defaults');
const validateConfig = require('./config/validateConfig');

// Utilities and Errors
const {
  SecurityError,
  RateLimitError,
  AuthenticationError,
  ForbiddenError,
  PayloadTooLargeError,
  ValidationError,
  ThreatDetectedError,
  ConfigurationError
} = require('./utils/errors');

const { sendSecurityResponse } = require('./utils/response');
const {
  SecurityLogger,
  defaultLogger,
  redact,
  getRequestId,
  DEFAULT_SENSITIVE_KEYS
} = require('./utils/logger');

module.exports = {
  // Primary Middlewares
  rateLimiter,
  createRateLimiter,
  defaultKeyGenerator,

  apiKeyAuth,
  createApiKeyAuth,
  extractApiKey,

  ipFilter,
  createIpFilter,

  requestSize,
  createRequestSize,
  parseContentLength,

  securityHeaders,
  createSecurityHeaders,

  requestValidator,
  createRequestValidator,
  formatIssues,

  threatDetector,
  createThreatDetector,

  // Security Helpers
  generateApiKey,
  hashApiKey,
  secureCompare,
  isKeyExpired,

  parseIp,
  formatIp,
  parseRule,
  matchesRule,
  isIpInRules,
  compileRules,
  getClientIp,

  DEFAULT_THREAT_PATTERNS,
  scanValue,

  // Stores
  MemoryStore,
  RedisStore,

  // Configuration
  defaults,
  validateConfig,

  // Errors
  SecurityError,
  RateLimitError,
  AuthenticationError,
  ForbiddenError,
  PayloadTooLargeError,
  ValidationError,
  ThreatDetectedError,
  ConfigurationError,

  // Utilities
  sendSecurityResponse,
  SecurityLogger,
  defaultLogger,
  redact,
  getRequestId,
  DEFAULT_SENSITIVE_KEYS
};

