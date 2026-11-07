'use strict';

const defaults = require('../config/defaults');
const { validateThreatDetectorConfig } = require('../config/validateConfig');
const { DEFAULT_THREAT_PATTERNS, scanValue } = require('../security/detector');
const { ThreatDetectedError } = require('../utils/errors');
const { sendSecurityResponse } = require('../utils/response');
const { defaultLogger } = require('../utils/logger');

/**
 * Creates threat detection middleware.
 *
 * @param {Object} [userOptions]
 * @param {'reject'|'log'|'pass'} [userOptions.action='reject'] - Action on threat detection.
 * @param {number} [userOptions.statusCode=403] - HTTP status code when rejected.
 * @param {string} [userOptions.message] - Custom rejection message.
 * @param {boolean} [userOptions.inspectUrl=true] - Inspect URL path.
 * @param {boolean} [userOptions.inspectQuery=true] - Inspect query parameters.
 * @param {boolean} [userOptions.inspectBody=true] - Inspect request body.
 * @param {boolean} [userOptions.inspectHeaders=false] - Inspect headers (default false to prevent false positives).
 * @param {Array<string|RegExp>} [userOptions.whitelistedPaths=[]] - Paths to bypass threat detection.
 * @param {string[]} [userOptions.whitelistedKeys=[]] - Field names to bypass inspection.
 * @param {Array<Object>} [userOptions.customRules=[]] - Custom threat rules.
 * @param {Function} [userOptions.handler] - Custom response handler.
 * @param {import('../utils/logger').SecurityLogger} [userOptions.logger] - Logger instance.
 * @returns {import('express').RequestHandler}
 */
function createThreatDetector(userOptions = {}) {
  validateThreatDetectorConfig(userOptions);

  const options = {
    ...defaults.threatDetector,
    ...userOptions
  };

  const logger = options.logger || defaultLogger;
  const allRules = [...DEFAULT_THREAT_PATTERNS, ...(options.customRules || [])];
  const whitelistedKeys = (options.whitelistedKeys || []).map((k) => k.toLowerCase());

  return function threatDetectorMiddleware(req, res, next) {
    if (options.action === 'pass') {
      return next();
    }

    const currentPath = req.originalUrl || req.path || req.url || '';

    // Check whitelisted paths
    if (options.whitelistedPaths && options.whitelistedPaths.length > 0) {
      const isWhitelisted = options.whitelistedPaths.some((p) =>
        typeof p === 'string' ? (currentPath === p || currentPath.startsWith(p)) : (p instanceof RegExp && p.test(currentPath))
      );
      if (isWhitelisted) {
        return next();
      }
    }

    const detectedThreats = [];

    // 1. Inspect URL (path and raw query)
    if (options.inspectUrl) {
      let rawUrl = req.url || '';
      try {
        rawUrl = decodeURIComponent(rawUrl);
      } catch {
        // malformed URI encoding could itself be an attack vector
        detectedThreats.push({
          ruleId: 'MALFORMED_URI',
          ruleName: 'Malformed URI Encoding',
          path: 'url',
          snippet: req.url,
          severity: 'high'
        });
      }

      if (rawUrl) {
        detectedThreats.push(...scanValue(rawUrl, allRules, 'url', whitelistedKeys));
      }
    }

    // 2. Inspect Query
    if (options.inspectQuery && req.query && typeof req.query === 'object') {
      detectedThreats.push(...scanValue(req.query, allRules, 'query', whitelistedKeys));
    }

    // 3. Inspect Body
    if (options.inspectBody && req.body && typeof req.body === 'object') {
      detectedThreats.push(...scanValue(req.body, allRules, 'body', whitelistedKeys));
    }

    // 4. Inspect Headers
    if (options.inspectHeaders && req.headers && typeof req.headers === 'object') {
      // Exclude standard headers that regularly contain symbols
      const ignoredHeaders = ['user-agent', 'accept', 'cookie', 'host', 'authorization'];
      const headersToScan = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (!ignoredHeaders.includes(k.toLowerCase())) {
          headersToScan[k] = v;
        }
      }
      detectedThreats.push(...scanValue(headersToScan, allRules, 'headers', whitelistedKeys));
    }

    if (detectedThreats.length > 0) {
      req.detectedThreats = detectedThreats;

      logger.warn('THREAT_DETECTED', `Threat patterns detected on ${req.method} ${currentPath}`, {
        req,
        details: {
          threatCount: detectedThreats.length,
          threats: detectedThreats.map((t) => ({ ruleId: t.ruleId, path: t.path, severity: t.severity }))
        }
      });

      if (options.action === 'reject') {
        const error = new ThreatDetectedError(options.message, options.statusCode, {
          threats: detectedThreats.map((t) => ({ ruleId: t.ruleId, severity: t.severity }))
        });
        return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
      }
    }

    return next();
  };
}

module.exports = {
  threatDetector: createThreatDetector,
  createThreatDetector
};

