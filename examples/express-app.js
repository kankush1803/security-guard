'use strict';

const express = require('express');
const { z } = require('zod');
const {
  securityHeaders,
  rateLimiter,
  requestSize,
  ipFilter,
  threatDetector,
  apiKeyAuth,
  requestValidator,
  generateApiKey,
  SecurityLogger
} = require('../src');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize custom security logger
const logger = new SecurityLogger({
  level: 'info',
  customLogger: (event) => {
    console.log(`[SECURITY AUDIT] [${event.level}] ${event.eventType} - ${event.message}`, {
      reqId: event.requestId,
      ip: event.ip,
      path: event.path
    });
  }
});

// Generate sample demonstration API keys
const adminKey = generateApiKey({ prefix: 'sag_admin_' });
const clientKey = generateApiKey({ prefix: 'sag_client_' });

console.log('--- Secure API Guard Demo Credentials ---');
console.log('Admin API Key:  ', adminKey.key);
console.log('Client API Key: ', clientKey.key);
console.log('-----------------------------------------');

// 1. Global Security Headers (Hardened Helmet default + custom API options)
app.use(
  securityHeaders({
    noIndex: true, // Prevents search engines from indexing API endpoints
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"]
      }
    }
  })
);

// 2. Request Size Protection (Rejects oversized payloads before buffer exhaustion)
app.use(
  requestSize({
    maxSize: '1mb',
    logger
  })
);

// 3. Global Rate Limiter (100 requests per 15 minutes per IP)
app.use(
  rateLimiter({
    windowMs: 15 * 60 * 1000,
    maxRequests: 100,
    logger
  })
);

// 4. Global Threat Detection (Heuristic inspection for path traversal, command injection, SSTI)
app.use(
  threatDetector({
    action: 'reject',
    whitelistedPaths: ['/health', '/docs'],
    whitelistedKeys: ['markdown', 'description'],
    logger
  })
);

// Body Parser
app.use(express.json());

// Public Endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// IP-restricted Internal Endpoint (CIDR Allowlist)
app.get(
  '/api/internal/metrics',
  ipFilter({
    mode: 'allowlist',
    allowlist: ['127.0.0.1', '::1', '10.0.0.0/8'],
    logger
  }),
  (req, res) => {
    res.json({
      success: true,
      metrics: { uptime: process.uptime(), memory: process.memoryUsage() }
    });
  }
);

// Protected Endpoint with API Key Authentication and Strict Zod Validation
const createProductSchema = z.object({
  title: z.string().min(3).max(100),
  price: z.number().positive(),
  category: z.enum(['electronics', 'books', 'apparel']),
  tags: z.array(z.string()).optional()
});

app.post(
  '/api/v1/products',
  apiKeyAuth({
    keys: [
      {
        id: 'admin_user',
        name: 'Operations Admin',
        hash: adminKey.hash, // Stored as hash, never plaintext!
        permissions: ['products:write']
      },
      {
        id: 'read_only_client',
        name: 'Partner Service',
        hash: clientKey.hash,
        permissions: ['products:read']
      }
    ],
    requiredPermissions: ['products:write'],
    logger
  }),
  requestValidator({
    body: createProductSchema
  }),
  (req, res) => {
    res.status(201).json({
      success: true,
      message: 'Product created successfully',
      data: req.validated.body,
      createdBy: req.apiKey.name
    });
  }
);

// Stricter Route-specific Rate Limiter for Login/Auth
const authLimiter = rateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 5, // 5 requests per minute
  message: 'Too many login attempts, please try again in 1 minute.'
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  res.json({ success: true, message: 'Authentication challenge accepted' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[secure-api-guard] Demo application running on http://localhost:${PORT}`);
  });
}

module.exports = app;

