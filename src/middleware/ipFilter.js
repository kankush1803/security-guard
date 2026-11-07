'use strict';

const defaults = require('../config/defaults');
const { validateIpFilterConfig } = require('../config/validateConfig');
const { compileRules, isIpInRules, getClientIp } = require('../security/ipAddress');
const { ForbiddenError } = require('../utils/errors');
const { sendSecurityResponse } = require('../utils/response');
const { defaultLogger } = require('../utils/logger');

/**
 * Creates IP filtering middleware for Express.
 *
 * @param {Object} [userOptions]
 * @param {'allowlist'|'blocklist'} [userOptions.mode='blocklist']
 * @param {string[]} [userOptions.allowlist=[]] - Array of IPs or CIDRs to allow.
 * @param {string[]} [userOptions.blocklist=[]] - Array of IPs or CIDRs to block.
 * @param {boolean|string[]|number} [userOptions.trustProxy=false] - Proxy trusting strategy.
 * @param {Function} [userOptions.getIp] - Custom IP extraction function.
 * @param {number} [userOptions.statusCode=403] - Status code on rejection.
 * @param {string} [userOptions.message] - Custom error message.
 * @param {Function} [userOptions.handler] - Custom response handler.
 * @param {import('../utils/logger').SecurityLogger} [userOptions.logger] - Logger instance.
 * @returns {import('express').RequestHandler}
 */
function createIpFilter(userOptions = {}) {
  validateIpFilterConfig(userOptions);

  const options = {
    ...defaults.ipFilter,
    ...userOptions
  };

  const logger = options.logger || defaultLogger;

  // Pre-compile IP and CIDR rules once at initialization
  const compiledAllowlist = compileRules(options.allowlist);
  const compiledBlocklist = compileRules(options.blocklist);

  return function ipFilterMiddleware(req, res, next) {
    const clientIp = getClientIp(req, options);

    if (options.mode === 'allowlist') {
      const allowed = isIpInRules(clientIp, compiledAllowlist);
      if (!allowed) {
        logger.warn('IP_ACCESS_DENIED', `IP ${clientIp} not in allowlist`, {
          req,
          ip: clientIp,
          details: { mode: 'allowlist' }
        });
        const error = new ForbiddenError(options.message);
        return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
      }
    } else {
      // Default: blocklist mode
      const blocked = isIpInRules(clientIp, compiledBlocklist);
      if (blocked) {
        logger.warn('IP_BLOCKED', `IP ${clientIp} is blocklisted`, {
          req,
          ip: clientIp,
          details: { mode: 'blocklist' }
        });
        const error = new ForbiddenError(options.message);
        return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
      }
    }

    // Attach verified client IP to request for downstream handlers
    req.clientIp = clientIp;
    return next();
  };
}

module.exports = {
  ipFilter: createIpFilter,
  createIpFilter
};

