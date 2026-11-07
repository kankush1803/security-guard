'use strict';

module.exports = {
  rateLimiter: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    statusCode: 429,
    message: 'Too many requests, please try again later.',
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    store: 'memory'
  },

  apiKeyAuth: {
    headerName: 'x-api-key',
    queryParam: null, // by default, disallow API key in query strings (security best practice)
    allowBearer: true, // allow Authorization: Bearer <key>
    hashAlgorithm: 'sha256',
    statusCode: 401,
    message: 'Unauthorized: Invalid or missing API key.',
    forbiddenStatusCode: 403,
    forbiddenMessage: 'Forbidden: API key has expired or has been revoked.'
  },

  ipFilter: {
    mode: 'blocklist', // 'allowlist' | 'blocklist'
    allowlist: [],
    blocklist: [],
    trustProxy: false,
    statusCode: 403,
    message: 'Forbidden: Access denied for your IP address.'
  },

  requestSize: {
    maxSize: '1mb',
    statusCode: 413,
    message: 'Payload Too Large: Request body exceeds maximum allowed size.'
  },

  securityHeaders: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        fontSrc: ["'self'", 'https:', 'data:'],
        formAction: ["'self'"],
        frameAncestors: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
        upgradeInsecureRequests: []
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    referrerPolicy: { policy: 'no-referrer' },
    xssFilter: true
  },

  requestValidator: {
    statusCode: 400,
    message: 'Validation failed: Invalid request parameters.'
  },

  threatDetector: {
    action: 'reject', // 'reject' | 'log' | 'pass'
    statusCode: 403,
    message: 'Forbidden: Suspicious request pattern detected.',
    inspectUrl: true,
    inspectQuery: true,
    inspectBody: true,
    inspectHeaders: false,
    whitelistedPaths: [],
    customRules: []
  },

  logger: {
    enabled: true,
    level: 'warn',
    redactFields: []
  }
};

