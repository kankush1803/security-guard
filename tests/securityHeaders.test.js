'use strict';

const express = require('express');
const request = require('supertest');
const { securityHeaders } = require('../src');

describe('Security Headers Middleware (Helmet Integration)', () => {
  it('should set secure default headers on responses', async () => {
    const app = express();
    app.use(securityHeaders());
    app.get('/api/resource', (req, res) => res.json({ ok: true }));

    const res = await request(app).get('/api/resource');

    expect(res.status).toBe(200);
    // X-Content-Type-Options
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    // X-Frame-Options
    expect(res.headers['x-frame-options']).toBe('DENY');
    // Referrer-Policy
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    // Content-Security-Policy
    expect(res.headers['content-security-policy']).toBeDefined();
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    // Permissions-Policy
    expect(res.headers['permissions-policy']).toBeDefined();
    // X-Powered-By should NOT be present (hidden)
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('should support custom CSP configuration', async () => {
    const app = express();
    app.use(
      securityHeaders({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'none'"],
            connectSrc: ["'self'", 'https://api.example.com']
          }
        }
      })
    );
    app.get('/api/custom', (req, res) => res.json({ ok: true }));

    const res = await request(app).get('/api/custom');
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['content-security-policy']).toContain('https://api.example.com');
  });

  it('should set X-Robots-Tag when noIndex is enabled', async () => {
    const app = express();
    app.use(
      securityHeaders({
        noIndex: true
      })
    );
    app.get('/private', (req, res) => res.json({ ok: true }));

    const res = await request(app).get('/private');
    expect(res.headers['x-robots-tag']).toBe('noindex, nofollow, noarchive');
  });
});

