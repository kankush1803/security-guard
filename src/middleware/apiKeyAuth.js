'use strict';

const defaults = require('../config/defaults');
const { validateApiKeyAuthConfig } = require('../config/validateConfig');
const { hashApiKey, secureCompare, isKeyExpired } = require('../security/apiKey');
const { AuthenticationError, ForbiddenError } = require('../utils/errors');
const { sendSecurityResponse } = require('../utils/response');
const { defaultLogger } = require('../utils/logger');

/**
 * Extracts API key from request headers or query parameters.
 *
 * @param {import('express').Request} req
 * @param {Object} options
 * @returns {string|null}
 */
function extractApiKey(req, options) {
  const headerName = options.headerName.toLowerCase();

  // 1. Direct header match
  if (req.headers && req.headers[headerName]) {
    const val = req.headers[headerName];
    return Array.isArray(val) ? val[0].trim() : String(val).trim();
  }

  // 2. Authorization header (Bearer or Api-Key)
  if (options.allowBearer && req.headers && req.headers.authorization) {
    const authHeader = String(req.headers.authorization).trim();
    const bearerMatch = authHeader.match(/^(?:Bearer|Api-Key)\s+(.+)$/i);
    if (bearerMatch) {
      return bearerMatch[1].trim();
    }
  }

  // 3. Query parameter (only if explicitly enabled)
  if (options.queryParam && req.query && req.query[options.queryParam]) {
    const qVal = req.query[options.queryParam];
    return Array.isArray(qVal) ? qVal[0].trim() : String(qVal).trim();
  }

  return null;
}

/**
 * Creates API key authentication middleware.
 *
 * @param {Object} [userOptions]
 * @param {string} [userOptions.headerName='x-api-key'] - Header name to check.
 * @param {string|null} [userOptions.queryParam=null] - Query parameter name (if allowed).
 * @param {boolean} [userOptions.allowBearer=true] - Allow Authorization: Bearer <key>.
 * @param {string} [userOptions.hashAlgorithm='sha256'] - Hash algorithm.
 * @param {Array<string|Object>} [userOptions.keys] - List of keys or key objects.
 * @param {Function} [userOptions.getKey] - Async function (hash, req) => keyRecord.
 * @param {Function} [userOptions.verifyKey] - Custom async verification function (rawKey, req).
 * @param {string[]} [userOptions.requiredPermissions] - Optional permissions required for this route.
 * @param {number} [userOptions.statusCode=401] - Status code for authentication failure.
 * @param {number} [userOptions.forbiddenStatusCode=403] - Status code for expired/forbidden key.
 * @param {string} [userOptions.message] - Custom error message for invalid key.
 * @param {string} [userOptions.forbiddenMessage] - Custom error message for expired/forbidden key.
 * @param {Function} [userOptions.handler] - Custom response handler.
 * @param {import('../utils/logger').SecurityLogger} [userOptions.logger] - Logger instance.
 * @returns {import('express').RequestHandler}
 */
function createApiKeyAuth(userOptions = {}) {
  validateApiKeyAuthConfig(userOptions);

  const options = {
    ...defaults.apiKeyAuth,
    ...userOptions
  };

  const logger = options.logger || defaultLogger;

  // Pre-process keys if static list provided
  // Stored format: array of { hash, id, name, expiresAt, permissions, metadata }
  let precomputedKeys = [];
  if (Array.isArray(options.keys)) {
    precomputedKeys = options.keys.map((item, idx) => {
      if (typeof item === 'string') {
        // Assume raw string key provided; hash it
        return {
          id: `key_${idx + 1}`,
          hash: hashApiKey(item, options.hashAlgorithm),
          expiresAt: null,
          permissions: []
        };
      } else if (typeof item === 'object' && item !== null) {
        // If already hashed (item.hash), use it; otherwise hash item.key
        const hash = item.hash || (item.key ? hashApiKey(item.key, options.hashAlgorithm) : null);
        return {
          id: item.id || `key_${idx + 1}`,
          name: item.name,
          hash,
          expiresAt: item.expiresAt || null,
          permissions: Array.isArray(item.permissions) ? item.permissions : [],
          metadata: item.metadata || {}
        };
      }
      return null;
    }).filter(Boolean);
  }

  return async function apiKeyAuthMiddleware(req, res, next) {
    const rawKey = extractApiKey(req, options);

    if (!rawKey) {
      logger.warn('API_KEY_AUTH_FAILED', 'API key missing in request', { req });
      const error = new AuthenticationError(options.message);
      return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
    }

    try {
      // 1. Custom verify function
      if (typeof options.verifyKey === 'function') {
        const verifyResult = await options.verifyKey(rawKey, req);
        if (!verifyResult) {
          logger.warn('API_KEY_AUTH_FAILED', 'API key verification rejected by verifyKey', { req });
          const error = new AuthenticationError(options.message);
          return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
        }

        const keyInfo = typeof verifyResult === 'object' ? verifyResult : {};
        if (isKeyExpired(keyInfo)) {
          logger.warn('API_KEY_EXPIRED', `API key ${keyInfo.id || ''} has expired`, { req });
          const error = new ForbiddenError(options.forbiddenMessage);
          return sendSecurityResponse(req, res, error, options.forbiddenStatusCode, options.handler);
        }

        req.apiKey = {
          id: keyInfo.id || 'custom',
          name: keyInfo.name,
          permissions: keyInfo.permissions || [],
          metadata: keyInfo.metadata || {}
        };
        return next();
      }

      // Compute hash of incoming key
      const incomingHash = hashApiKey(rawKey, options.hashAlgorithm);
      let matchedRecord = null;

      // 2. Custom getKey lookup function
      if (typeof options.getKey === 'function') {
        const retrieved = await options.getKey(incomingHash, req);
        if (retrieved) {
          const storedHash = retrieved.hash || (retrieved.key ? hashApiKey(retrieved.key, options.hashAlgorithm) : null);
          if (storedHash && secureCompare(incomingHash, storedHash)) {
            matchedRecord = retrieved;
          }
        }
      } else {
        // 3. Search precomputed static keys using constant-time comparison
        for (const candidate of precomputedKeys) {
          if (candidate.hash && secureCompare(incomingHash, candidate.hash)) {
            matchedRecord = candidate;
            break;
          }
        }
      }

      if (!matchedRecord) {
        logger.warn('API_KEY_AUTH_FAILED', 'Invalid API key provided', { req });
        const error = new AuthenticationError(options.message);
        return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
      }

      // Check expiration
      if (isKeyExpired(matchedRecord)) {
        logger.warn('API_KEY_EXPIRED', `API key ${matchedRecord.id || ''} has expired`, { req });
        const error = new ForbiddenError(options.forbiddenMessage);
        return sendSecurityResponse(req, res, error, options.forbiddenStatusCode, options.handler);
      }

      // Check permissions if required
      if (options.requiredPermissions && options.requiredPermissions.length > 0) {
        const keyPermissions = Array.isArray(matchedRecord.permissions) ? matchedRecord.permissions : [];
        const hasAllPermissions = options.requiredPermissions.every((perm) => keyPermissions.includes(perm));

        if (!hasAllPermissions) {
          logger.warn('API_KEY_INSUFFICIENT_PERMISSIONS', `API key ${matchedRecord.id} lacks required permissions`, {
            req,
            details: { required: options.requiredPermissions, actual: keyPermissions }
          });
          const error = new ForbiddenError('Forbidden: Insufficient permissions for this API resource.');
          return sendSecurityResponse(req, res, error, options.forbiddenStatusCode, options.handler);
        }
      }

      // Attach sanitized key record (NEVER the plaintext key or raw hash)
      req.apiKey = {
        id: matchedRecord.id,
        name: matchedRecord.name,
        permissions: matchedRecord.permissions || [],
        metadata: matchedRecord.metadata || {}
      };

      return next();
    } catch (err) {
      logger.error('API_KEY_AUTH_ERROR', `Internal error during API key verification: ${err.message}`, { req });
      return next(err);
    }
  };
}

module.exports = {
  apiKeyAuth: createApiKeyAuth,
  createApiKeyAuth,
  extractApiKey
};

