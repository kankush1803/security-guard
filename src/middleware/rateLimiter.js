'use strict';

const rateLimit = require('express-rate-limit');
const defaults = require('../config/defaults');
const { validateRateLimiterConfig } = require('../config/validateConfig');
const { formatIp } = require('../security/ipAddress');
const { MemoryStore } = require('../stores/memoryStore');
const { RedisStore } = require('../stores/redisStore');
const { RateLimitError } = require('../utils/errors');
const { sendSecurityResponse } = require('../utils/response');
const { defaultLogger } = require('../utils/logger');

/**
 * Default key generator based on client IP.
 *
 * @param {import('express').Request} req
 * @returns {string}
 */
function defaultKeyGenerator(req) {
  const rawIp = req.ip || (req.socket && req.socket.remoteAddress) || '127.0.0.1';
  return formatIp(rawIp);
}

/**
 * Creates a rate limiter middleware for Express.
 *
 * @param {Object} [userOptions] - Rate limiter configuration options.
 * @param {number} [userOptions.windowMs=900000] - Window duration in ms (15 mins default).
 * @param {number} [userOptions.maxRequests=100] - Maximum requests allowed per window.
 * @param {number} [userOptions.max] - Alias for maxRequests.
 * @param {number} [userOptions.statusCode=429] - HTTP status code on limit exceed.
 * @param {string} [userOptions.message] - Custom message on rate limit.
 * @param {Function} [userOptions.keyGenerator] - Custom key generation function (req => string).
 * @param {Function} [userOptions.skip] - Function to skip rate limiting (req => boolean).
 * @param {any} [userOptions.store] - Store instance ('memory', 'redis', or custom Store).
 * @param {any} [userOptions.redisClient] - Redis client if store is 'redis'.
 * @param {Function} [userOptions.handler] - Custom error handler.
 * @param {import('../utils/logger').SecurityLogger} [userOptions.logger] - Logger instance.
 * @returns {import('express').RequestHandler}
 */
function createRateLimiter(userOptions = {}) {
  validateRateLimiterConfig(userOptions);

  const options = {
    ...defaults.rateLimiter,
    ...userOptions
  };

  const limit = options.maxRequests !== undefined ? options.maxRequests : (options.max !== undefined ? options.max : 100);
  const logger = options.logger || defaultLogger;

  // Resolve Store
  let storeInstance;
  if (options.store === 'redis' || (options.redisClient && !options.store)) {
    if (!options.redisClient) {
      throw new Error('RateLimiter: "redisClient" must be provided when store is "redis".');
    }
    storeInstance = new RedisStore({
      client: options.redisClient,
      windowMs: options.windowMs,
      prefix: options.redisPrefix,
      passOnConnectionError: options.passOnRedisError,
      logger
    });
  } else if (typeof options.store === 'object' && options.store !== null) {
    storeInstance = options.store;
  } else {
    // Default in-memory store
    storeInstance = new MemoryStore({
      windowMs: options.windowMs
    });
  }

  const keyGenerator = options.keyGenerator || defaultKeyGenerator;

  const limiterMiddleware = rateLimit({
    windowMs: options.windowMs,
    limit,
    standardHeaders: options.standardHeaders,
    legacyHeaders: options.legacyHeaders,
    store: storeInstance,
    keyGenerator: (req, res) => keyGenerator(req),
    skip: options.skip || (() => false),
    handler: (req, res, next, rateLimitOptions) => {
      const clientKey = keyGenerator(req);
      const retryAfterSeconds = Math.ceil(options.windowMs / 1000);

      logger.warn('RATE_LIMIT_EXCEEDED', `Rate limit exceeded for client: ${clientKey}`, {
        req,
        ip: clientKey,
        details: {
          limit,
          windowMs: options.windowMs,
          retryAfter: retryAfterSeconds
        }
      });

      const error = new RateLimitError(options.message, {
        limit,
        windowMs: options.windowMs,
        retryAfter: retryAfterSeconds
      });

      sendSecurityResponse(req, res, error, options.statusCode, options.handler);
    }
  });

  return limiterMiddleware;
}

module.exports = {
  rateLimiter: createRateLimiter,
  createRateLimiter,
  defaultKeyGenerator
};

