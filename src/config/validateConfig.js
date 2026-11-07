'use strict';

const bytes = require('bytes');
const { ConfigurationError } = require('../utils/errors');

/**
 * Validate Rate Limiter configuration options.
 *
 * @param {Object} options
 */
function validateRateLimiterConfig(options = {}) {
  if (options.windowMs !== undefined) {
    if (typeof options.windowMs !== 'number' || !Number.isFinite(options.windowMs) || options.windowMs <= 0) {
      throw new ConfigurationError('RateLimiter: "windowMs" must be a positive number of milliseconds.');
    }
  }

  const max = options.maxRequests !== undefined ? options.maxRequests : options.max;
  if (max !== undefined) {
    if (typeof max !== 'number' || !Number.isFinite(max) || max < 0) {
      throw new ConfigurationError('RateLimiter: "maxRequests" (or "max") must be a non-negative number.');
    }
  }

  if (options.statusCode !== undefined) {
    if (typeof options.statusCode !== 'number' || options.statusCode < 100 || options.statusCode > 599) {
      throw new ConfigurationError('RateLimiter: "statusCode" must be a valid HTTP status code between 100 and 599.');
    }
  }

  if (options.keyGenerator !== undefined && typeof options.keyGenerator !== 'function') {
    throw new ConfigurationError('RateLimiter: "keyGenerator" must be a function.');
  }

  if (options.skip !== undefined && typeof options.skip !== 'function') {
    throw new ConfigurationError('RateLimiter: "skip" must be a function.');
  }
}

/**
 * Validate API Key Auth configuration options.
 *
 * @param {Object} options
 */
function validateApiKeyAuthConfig(options = {}) {
  if (options.headerName !== undefined) {
    if (typeof options.headerName !== 'string' || options.headerName.trim().length === 0) {
      throw new ConfigurationError('ApiKeyAuth: "headerName" must be a non-empty string.');
    }
  }

  if (options.queryParam !== undefined && options.queryParam !== null) {
    if (typeof options.queryParam !== 'string' || options.queryParam.trim().length === 0) {
      throw new ConfigurationError('ApiKeyAuth: "queryParam" must be a non-empty string or null.');
    }
  }

  if (options.keys !== undefined) {
    if (!Array.isArray(options.keys) && typeof options.keys !== 'object') {
      throw new ConfigurationError('ApiKeyAuth: "keys" must be an array or object.');
    }
  }

  if (options.getKey !== undefined && typeof options.getKey !== 'function') {
    throw new ConfigurationError('ApiKeyAuth: "getKey" must be a function.');
  }

  if (options.verifyKey !== undefined && typeof options.verifyKey !== 'function') {
    throw new ConfigurationError('ApiKeyAuth: "verifyKey" must be a function.');
  }
}

/**
 * Validate IP Filter configuration options.
 *
 * @param {Object} options
 */
function validateIpFilterConfig(options = {}) {
  if (options.mode !== undefined) {
    if (options.mode !== 'allowlist' && options.mode !== 'blocklist') {
      throw new ConfigurationError('IpFilter: "mode" must be either "allowlist" or "blocklist".');
    }
  }

  if (options.allowlist !== undefined && !Array.isArray(options.allowlist)) {
    throw new ConfigurationError('IpFilter: "allowlist" must be an array of IP strings or CIDR notations.');
  }

  if (options.blocklist !== undefined && !Array.isArray(options.blocklist)) {
    throw new ConfigurationError('IpFilter: "blocklist" must be an array of IP strings or CIDR notations.');
  }

  if (options.getIp !== undefined && typeof options.getIp !== 'function') {
    throw new ConfigurationError('IpFilter: "getIp" must be a function.');
  }
}

/**
 * Validate Request Size configuration options.
 *
 * @param {Object} options
 */
function validateRequestSizeConfig(options = {}) {
  if (options.maxSize !== undefined) {
    if (typeof options.maxSize === 'string') {
      const parsed = bytes.parse(options.maxSize);
      if (parsed === null || parsed <= 0) {
        throw new ConfigurationError(`RequestSize: "maxSize" string "${options.maxSize}" cannot be parsed into a valid byte limit.`);
      }
    } else if (typeof options.maxSize === 'number') {
      if (!Number.isFinite(options.maxSize) || options.maxSize <= 0) {
        throw new ConfigurationError('RequestSize: "maxSize" number must be greater than 0 bytes.');
      }
    } else {
      throw new ConfigurationError('RequestSize: "maxSize" must be a number of bytes or a valid byte string (e.g. "1mb", "500kb").');
    }
  }
}

/**
 * Validate Threat Detector configuration options.
 *
 * @param {Object} options
 */
function validateThreatDetectorConfig(options = {}) {
  if (options.action !== undefined) {
    if (!['reject', 'log', 'pass'].includes(options.action)) {
      throw new ConfigurationError('ThreatDetector: "action" must be "reject", "log", or "pass".');
    }
  }

  if (options.customRules !== undefined && !Array.isArray(options.customRules)) {
    throw new ConfigurationError('ThreatDetector: "customRules" must be an array of rule objects or functions.');
  }

  if (options.whitelistedPaths !== undefined && !Array.isArray(options.whitelistedPaths)) {
    throw new ConfigurationError('ThreatDetector: "whitelistedPaths" must be an array of strings or RegExps.');
  }
}

module.exports = {
  validateRateLimiterConfig,
  validateApiKeyAuthConfig,
  validateIpFilterConfig,
  validateRequestSizeConfig,
  validateThreatDetectorConfig
};

