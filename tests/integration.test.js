'use strict';

const express = require('express');
const request = require('supertest');
const { z } = require('zod');
const {
  rateLimiter,
  apiKeyAuth,
  ipFilter,
  requestSize,
  securityHeaders,
  threatDetector,
  requestValidator,
  generateApiKey
} = require('../src');

describe('Full Security Pipeline Integration Test', () => {
  const masterKey = generateApiKey({ prefix: 'sag_app_' });

  function createSecureApp() {
    const app = express();

    // 1. Security Headers (Helmet)
    app.use(securityHeaders({ noIndex: true }));

    // 2. Request Size Protection
    app.use(requestSize({ maxSize: '500kb' }));

    // 3. Rate Limiter
    app.use(
      rateLimiter({
        windowMs: 60000,
        maxRequests: 50
      })
    );

    // 4. IP Filter (Block bad subnet)
    app.use(
      ipFilter({
        mode: 'blocklist',
        blocklist: ['198.51.100.0/24'],
        getIp: (req) => req.headers['x-client-ip'] || '127.0.0.1'
      })
    );

    // 5. Threat Detector
    app.use(
      threatDetector({
        action: 'reject',
        whitelistedPaths: ['/health']
      })
    );

    // Body parsing after size check
    app.use(express.json());

    // Public health check route
    app.get('/health', (req, res) => res.json({ status: 'ok' }));

    // Protected API route with API key & validation
    const itemSchema = z.object({
      name: z.string().min(2),
      price: z.number().positive()
    });

    app.post(
      '/api/private/items',
      apiKeyAuth({
        keys: [{ id: 'admin-1', key: masterKey.key, permissions: ['items:create'] }],
        requiredPermissions: ['items:create']
      }),
      requestValidator({ body: itemSchema }),
      (req, res) => {
        res.json({
          success: true,
          message: 'Item created',
          item: req.validated.body,
          caller: req.apiKey
        });
      }
    );

    return app;
  }

  it('should successfully pass when all security checks are satisfied', async () => {
    const app = createSecureApp();

    const res = await request(app)
      .post('/api/private/items')
      .set('x-api-key', masterKey.key)
      .set('x-client-ip', '192.168.1.55')
      .send({
        name: 'Quantum Sensor',
        price: 499.99
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.item.name).toBe('Quantum Sensor');
    expect(res.body.caller.id).toBe('admin-1');

    // Verify security headers were applied
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['x-robots-tag']).toBe('noindex, nofollow, noarchive');
  });

  it('should intercept blocked IP early in the pipeline', async () => {
    const app = createSecureApp();

    const res = await request(app)
      .post('/api/private/items')
      .set('x-client-ip', '198.51.100.12') // In blocked CIDR
      .set('x-api-key', masterKey.key)
      .send({ name: 'Valid Item', price: 100 });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('FORBIDDEN');
  });

  it('should intercept path traversal threats before authentication', async () => {
    const app = createSecureApp();

    const res = await request(app)
      .post('/api/private/items?folder=../../etc')
      .set('x-client-ip', '10.0.0.1')
      .set('x-api-key', masterKey.key)
      .send({ name: 'Valid Item', price: 100 });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('THREAT_DETECTED');
  });

  it('should reject unauthorized requests lacking API key', async () => {
    const app = createSecureApp();

    const res = await request(app)
      .post('/api/private/items')
      .set('x-client-ip', '10.0.0.1')
      .send({ name: 'Valid Item', price: 100 });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('should reject invalid payload schema when authenticated', async () => {
    const app = createSecureApp();

    const res = await request(app)
      .post('/api/private/items')
      .set('x-api-key', masterKey.key)
      .set('x-client-ip', '10.0.0.1')
      .send({ name: 'A', price: -50 }); // name too short, price negative

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
    expect(res.body.error.details.issues.length).toBe(2);
  });
});
