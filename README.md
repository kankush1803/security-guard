# secure-api-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org)
[![Express Support](https://img.shields.io/badge/express-4.x%20%7C%205.x-lightgrey.svg)](https://expressjs.com)

> Production-ready, battle-tested security middleware suite for Node.js and Express applications.

`secure-api-guard` provides cohesive, modular security controls for modern Express APIs: distributed rate limiting, cryptographically secure API key authentication, CIDR-aware IP filtering, payload size protection, HTTP security headers, request validation, threat detection, and credential-safe security logging.

---

## Table of Contents

1. [Package Introduction](#1-package-introduction)
2. [Features](#2-features)
3. [Installation Requirements](#3-installation-requirements)
4. [Installation](#4-installation)
5. [Quick Start](#5-quick-start)
6. [Individual Middleware Usage](#6-individual-middleware-usage)
   - [A. Security Headers](#a-security-headers)
   - [B. Rate Limiter](#b-rate-limiter)
   - [C. API Key Authentication](#c-api-key-authentication)
   - [D. IP Filtering](#d-ip-filtering)
   - [E. Request Size Protection](#e-request-size-protection)
   - [F. Request Validation (Zod & Custom)](#f-request-validation)
   - [G. Threat Detection](#g-threat-detection)
   - [H. Security Logging & Redaction](#h-security-logging--redaction)
7. [Redis Integration](#7-redis-integration)
8. [Configuration Options Reference](#8-configuration-options-reference)
9. [Error Response Format](#9-error-response-format)
10. [Security Considerations](#10-security-considerations)
11. [TypeScript Usage](#11-typescript-usage)
12. [Testing Instructions](#12-testing-instructions)
13. [Contributing](#13-contributing)
14. [License](#14-license)

---

## 1. Package Introduction

Securing production Node.js APIs usually requires piecing together fragmented, incompatible libraries with inconsistent error formats, missing IPv6 support, or naive proxy handling.

`secure-api-guard` was designed from the ground up for high-security, high-throughput environments:
- **Express 4 & Express 5 Compatible**: Works seamlessly with both legacy and modern Express routing architectures.
- **Zero In-Memory Plaintext Secrets**: Compares and stores SHA-256 hashed keys in constant time.
- **Fail-Safe Proxy Handling**: Rejects `X-Forwarded-For` spoofing by default.
- **Standardized Error Structures**: Machine-readable error codes and consistent JSON payloads without leaking stack traces.
- **Zero Information Leakage**: Automatic deep redaction of credentials in application logs.

---

## 2. Features

- **Rate Limiting**: IP-based sliding/fixed window rate limiter with in-memory storage or multi-instance Redis cluster support (atomic Lua scripts).
- **API Key Authentication**: Cryptographically random key generation, constant-time hash verification, permission scoping, and expiration support.
- **IP Allowlisting & Blocklisting**: IPv4, IPv6, and CIDR subnets powered by `ipaddr.js`.
- **Request Size Defense**: Content-Length verification, HTTP request smuggling prevention, and stream chunk inspection.
- **Security Headers**: Hardened Helmet baseline with CSP, HSTS, frame protection, and search engine de-indexing.
- **Schema Validation**: Seamless, optional Zod integration with structured field-level error messages.
- **Threat Detection**: Heuristic detection for directory traversal, command injection, null-byte injection, and prototype pollution.
- **Security Logger**: Structured event audit trail with automatic deep redaction of passwords, tokens, cookies, and secret fields.

---

## 3. Installation Requirements

- **Runtime**: Node.js `20.0.0` or higher.
- **Framework**: Express `4.x` or Express `5.x`.
- **Module System**: CommonJS (`require` / `module.exports`). TypeScript definitions are included out of the box.

Optional peer dependencies:
- `zod` (`>= 3.0.0`): Required only when using Zod schema validation.
- `redis` (`>= 4.0.0`) or `ioredis` (`>= 5.0.0`): Required only when configuring Redis-backed rate limiting.

---

## 4. Installation

```bash
# Core package
npm install secure-api-guard

# Optional: Add Zod if using schema validation
npm install zod

# Optional: Add ioredis or redis if using distributed rate limiting
npm install ioredis
```

---

## 5. Quick Start

```javascript
const express = require('express');
const {
  securityHeaders,
  rateLimiter,
  requestSize,
  apiKeyAuth
} = require('secure-api-guard');

const app = express();

// 1. Security Headers (CSP, HSTS, X-Content-Type-Options)
app.use(securityHeaders());

// 2. Global Rate Limiting (100 requests per 15 minutes per IP)
app.use(
  rateLimiter({
    windowMs: 15 * 60 * 1000,
    maxRequests: 100
  })
);

// 3. Request Size Limiting (Reject bodies exceeding 1MB)
app.use(
  requestSize({
    maxSize: '1mb'
  })
);

// 4. Protected Route with API Key Auth
app.get(
  '/api/private',
  apiKeyAuth({
    keys: [process.env.ADMIN_API_KEY]
  }),
  (req, res) => {
    res.json({
      success: true,
      message: 'Access granted'
    });
  }
);

app.listen(3000, () => {
  console.log('Secure API running on http://localhost:3000');
});
```

---

## 6. Individual Middleware Usage

### A. Security Headers

Powered by Helmet with secure default headers tuned for APIs:

```javascript
const { securityHeaders } = require('secure-api-guard');

app.use(
  securityHeaders({
    noIndex: true, // Adds X-Robots-Tag: noindex, nofollow, noarchive
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"]
      }
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  })
);
```

### B. Rate Limiter

Implements standard `RateLimit-*` (RFC draft-7) headers and returns HTTP 429 when limits are exceeded.

```javascript
const { rateLimiter } = require('secure-api-guard');

// Route-specific strict limiter (e.g. Login endpoint)
const loginLimiter = rateLimiter({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 5,
  message: 'Too many login attempts, please try again later.',
  keyGenerator: (req) => req.body.email || req.ip,
  skip: (req) => req.ip === '127.0.0.1' // Skip local testing
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
  res.json({ success: true });
});
```

### C. API Key Authentication

Supports cryptographic key generation, constant-time verification (`crypto.timingSafeEqual`), expiration checks, and role permissions.

#### Key Generation Utility

```javascript
const { generateApiKey } = require('secure-api-guard');

const { key, hash, prefix } = generateApiKey({
  prefix: 'sag_live_',
  bytes: 32
});

console.log('Provide key to client:', key);
console.log('Store this hash in database:', hash);
```

#### Middleware Verification

```javascript
const { apiKeyAuth } = require('secure-api-guard');

app.use(
  '/api/v1',
  apiKeyAuth({
    headerName: 'x-api-key', // default: 'x-api-key'
    allowBearer: true,       // Also allows "Authorization: Bearer <key>"
    // Lookup key by SHA-256 hash in database
    getKey: async (hash, req) => {
      const record = await db.apiKeys.findOne({ hash });
      if (!record) return null;
      return {
        id: record.id,
        name: record.clientName,
        hash: record.hash,
        expiresAt: record.expiresAt,
        permissions: record.scopes
      };
    },
    requiredPermissions: ['read:orders']
  })
);

app.get('/api/v1/orders', (req, res) => {
  // Safe metadata attached; raw key is NEVER attached to req.apiKey
  console.log('Caller ID:', req.apiKey.id);
  res.json({ orders: [] });
});
```

### D. IP Filtering

Filter requests by IPv4, IPv6, or CIDR blocks.

> **Security Warning on Proxies**: Never blindly trust `X-Forwarded-For`. Unless `trustProxy` is explicitly configured with your trusted load balancers/proxies, `secure-api-guard` only inspects the direct network socket IP address.

```javascript
const { ipFilter } = require('secure-api-guard');

// Allowlist mode: only specified subnet can access
app.use(
  '/admin',
  ipFilter({
    mode: 'allowlist',
    allowlist: [
      '127.0.0.1',
      '::1',
      '10.0.0.0/8',        // Private IPv4 CIDR
      '2001:db8::/32'     // IPv6 CIDR
    ],
    // Only trust X-Forwarded-For if request came from our trusted proxy IP
    trustProxy: ['172.16.0.10']
  })
);
```

### E. Request Size Protection

Protects against memory exhaustion and HTTP request smuggling before body parsers allocate memory.

```javascript
const { requestSize } = require('secure-api-guard');

// Must be placed before express.json()
app.use(
  requestSize({
    maxSize: '500kb',
    message: 'Payload Too Large: Maximum allowed body is 500KB.'
  })
);

app.use(express.json());
```

### F. Request Validation

Integrates seamlessly with [Zod](https://github.com/colinhacks/zod) to validate `body`, `query`, and `params`.

```javascript
const { z } = require('zod');
const { requestValidator } = require('secure-api-guard');

const userSchema = z.object({
  name: z.string().min(2).max(50),
  email: z.string().email(),
  age: z.number().int().positive().optional()
});

const querySchema = z.object({
  page: z.string().regex(/^\d+$/).transform(Number)
});

app.post(
  '/users',
  requestValidator({
    body: userSchema,
    query: querySchema
  }),
  (req, res) => {
    // Validated, type-safe data accessible on req.validated
    const { name, email } = req.validated.body;
    const { page } = req.validated.query;

    res.status(201).json({ success: true, user: { name, email, page } });
  }
);
```

### G. Threat Detection

Heuristic inspection for suspicious attack patterns in URLs, query strings, headers, and request bodies.

> **Defense-in-Depth Notice**: Threat pattern detection is a heuristic defense layer. It is not an alternative to parameterized SQL queries or contextual HTML encoding.

```javascript
const { threatDetector } = require('secure-api-guard');

app.use(
  threatDetector({
    action: 'reject', // 'reject' (403) | 'log' (logs warning) | 'pass'
    whitelistedPaths: ['/webhooks/incoming'],
    whitelistedKeys: ['markdown', 'articleContent'], // Prevent false positives on rich text
    customRules: [
      {
        id: 'CUSTOM_SIGNATURE',
        name: 'Block specific attack string',
        pattern: /malicious_pattern_regex/i,
        severity: 'high'
      }
    ]
  })
);
```

### H. Security Logging & Redaction

Record security events without ever leaking credentials or secrets:

```javascript
const { SecurityLogger, redact } = require('secure-api-guard');

const logger = new SecurityLogger({
  level: 'info',
  customLogger: (event) => {
    // Pipe to Winston, Pino, Datadog, CloudWatch, etc.
    myWinstonLogger.warn(event.message, event);
  }
});

// Deep redaction utility
const sanitized = redact({
  user: 'alice',
  password: 'mySecretPassword',
  tokens: [{ token: 'jwt-access-token' }]
});
// Result: { user: 'alice', password: '[REDACTED]', tokens: [{ token: '[REDACTED]' }] }
```

---

## 7. Redis Integration

For multi-instance deployments running behind Kubernetes, AWS ECS, or horizontal auto-scalers, use `RedisStore` to ensure atomic distributed rate limiting across all instances without race conditions.

```javascript
const Redis = require('ioredis');
const { rateLimiter, RedisStore } = require('secure-api-guard');

const redisClient = new Redis(process.env.REDIS_URL);

app.use(
  rateLimiter({
    windowMs: 60 * 1000,
    maxRequests: 100,
    store: 'redis',
    redisClient,
    passOnRedisError: true // Fail-open: avoids bringing down API if Redis cluster degrades
  })
);
```

---

## 8. Configuration Options Reference

### `rateLimiter(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `windowMs` | `number` | `900000` (15m) | Rate limiting window in milliseconds. |
| `maxRequests` | `number` | `100` | Maximum allowed hits per client in the window. |
| `keyGenerator` | `Function` | `(req) => req.ip` | Custom client identification function. |
| `skip` | `Function` | `() => false` | Condition to skip rate limiting for a request. |
| `store` | `'memory' \| 'redis' \| object` | `'memory'` | Storage adapter instance. |
| `redisClient` | `object` | `undefined` | Redis client instance (`ioredis` or `node-redis`). |
| `passOnRedisError` | `boolean` | `true` | Fail-open if Redis encounters connection errors. |
| `statusCode` | `number` | `429` | HTTP status code when limit exceeded. |
| `message` | `string` | `'Too many requests...'` | Rejection message. |

### `apiKeyAuth(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `headerName` | `string` | `'x-api-key'` | Custom header to read API key from. |
| `allowBearer` | `boolean` | `true` | Support `Authorization: Bearer <key>` header. |
| `queryParam` | `string \| null` | `null` | Allowed query parameter (disabled by default for security). |
| `keys` | `Array<string \| object>` | `[]` | Static list of keys or hashed key records. |
| `getKey` | `Function` | `undefined` | Async lookup function `(hash, req) => Promise<record>`. |
| `requiredPermissions` | `string[]` | `[]` | Permissions required on the key to proceed. |
| `statusCode` | `number` | `401` | Status code on missing or invalid key. |
| `forbiddenStatusCode` | `number` | `403` | Status code on expired key or missing permissions. |

### `ipFilter(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `mode` | `'allowlist' \| 'blocklist'` | `'blocklist'` | Filtering strategy. |
| `allowlist` | `string[]` | `[]` | List of allowed IP addresses or CIDR ranges. |
| `blocklist` | `string[]` | `[]` | List of blocked IP addresses or CIDR ranges. |
| `trustProxy` | `boolean \| string[] \| number` | `false` | Proxy trust policy. |
| `getIp` | `Function` | `undefined` | Custom IP resolver function. |
| `statusCode` | `number` | `403` | Status code on rejection. |

### `requestSize(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `maxSize` | `string \| number` | `'1mb'` | Maximum payload size (bytes or e.g. `'500kb'`). |
| `statusCode` | `number` | `413` | Status code on limit exceed. |

---

## 9. Error Response Format

All security rejections adhere to a uniform, clean JSON envelope:

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests, please try again later.",
    "details": {
      "limit": 100,
      "windowMs": 900000,
      "retryAfter": 60
    }
  }
}
```

Validation errors include granular field-level issues:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed: Invalid request parameters.",
    "details": {
      "issues": [
        {
          "field": "body.email",
          "message": "Invalid email address",
          "code": "invalid_string"
        }
      ]
    }
  }
}
```

---

## 10. Security Considerations

1. **Timing Attack Protection**: API key comparison uses `crypto.timingSafeEqual` over fixed-length cryptographic hashes to neutralize timing side channels.
2. **Hash at Rest**: Never store API keys in plaintext. Store the SHA-256 hash in your database, and provide only the raw key to your end users once upon creation.
3. **Never Blindly Trust `X-Forwarded-For`**: Attackers can spoof `X-Forwarded-For: 127.0.0.1`. Leave `trustProxy: false` unless running behind a reverse proxy whose direct IP you have verified.
4. **Defense in Depth**: Heuristic threat detection catches low-hanging exploits (e.g. `../../etc/passwd`), but you must always use parameterized database queries and validate inputs with schemas.

---

## 11. TypeScript Usage

Full TypeScript declarations are bundled in `src/types/index.d.ts`.

```typescript
import express, { Request, Response } from 'express';
import { rateLimiter, apiKeyAuth, RequestValidatorOptions } from 'secure-api-guard';

const app = express();

app.get(
  '/api/secure-profile',
  apiKeyAuth(),
  (req: Request, res: Response) => {
    // req.apiKey is strongly typed
    const callerId = req.apiKey?.id;
    res.json({ callerId });
  }
);
```

---

## 12. Testing Instructions

The package contains an automated test suite with Vitest and Supertest.

```bash
# Run unit and integration tests
npm test

# Run tests with code coverage analysis
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

---

## 13. Contributing

1. Fork the repository and create your feature branch: `git checkout -b feature/my-feature`.
2. Ensure all tests pass: `npm test`.
3. Verify test coverage: `npm run test:coverage`.
4. Commit your changes: `git commit -m 'feat: add feature'`.
5. Push to the branch: `git push origin feature/my-feature`.
6. Open a Pull Request.

---

## 14. License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

