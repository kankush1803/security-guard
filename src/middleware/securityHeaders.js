'use strict';

const helmet = require('helmet');
const defaults = require('../config/defaults');

/**
 * Creates security headers middleware powered by Helmet with hardened API defaults.
 *
 * @param {Object} [userOptions]
 * @param {boolean|Object} [userOptions.contentSecurityPolicy]
 * @param {boolean|Object} [userOptions.hsts]
 * @param {boolean|Object} [userOptions.frameguard]
 * @param {boolean} [userOptions.noSniff]
 * @param {boolean|Object} [userOptions.referrerPolicy]
 * @param {boolean} [userOptions.noIndex=false] - Adds X-Robots-Tag: noindex, nofollow
 * @param {boolean|string} [userOptions.permissionsPolicy=true] - Adds Permissions-Policy header
 * @returns {import('express').RequestHandler}
 */
function createSecurityHeaders(userOptions = {}) {
  const helmetOptions = {
    ...defaults.securityHeaders,
    ...userOptions
  };

  // Extract non-helmet custom options
  const noIndex = userOptions.noIndex === true;
  const permissionsPolicy = userOptions.permissionsPolicy !== undefined
    ? userOptions.permissionsPolicy
    : 'geolocation=(), camera=(), microphone=(), payment=()';

  delete helmetOptions.noIndex;
  delete helmetOptions.permissionsPolicy;

  const helmetMiddleware = helmet(helmetOptions);

  return function securityHeadersMiddleware(req, res, next) {
    // 1. Apply Helmet standard headers
    helmetMiddleware(req, res, (err) => {
      if (err) return next(err);

      // 2. Extra API security headers
      if (noIndex) {
        res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
      }

      if (permissionsPolicy && typeof permissionsPolicy === 'string') {
        res.setHeader('Permissions-Policy', permissionsPolicy);
      }

      return next();
    });
  };
}

module.exports = {
  securityHeaders: createSecurityHeaders,
  createSecurityHeaders
};

