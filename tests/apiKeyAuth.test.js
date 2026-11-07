'use strict';

const express = require('express');
const request = require('supertest');
const {
  apiKeyAuth,
  generateApiKey,
  hashApiKey,
  secureCompare,
  isKeyExpired
} = require('../src');

describe('API Key Authentication', () => {
  describe('Utility Functions', () => {
    it('should generate valid cryptographically secure API keys with prefix', () => {
      const generated = generateApiKey({ prefix: 'sag_prod_', bytes: 24 });
      expect(generated.key).toMatch(/^sag_prod_/);
      expect(generated.hash).toHaveLength(64); // SHA-256 hex string is 64 chars
      expect(generated.prefix).toBe('sag_prod_');

      // Verify that hashing the generated key matches the generated hash
      const computedHash = hashApiKey(generated.key);
      expect(computedHash).toBe(generated.hash);
    });

    it('should securely compare equal and non-equal hashes in constant time', () => {
      const hashA = hashApiKey('key-alpha');
      const hashB = hashApiKey('key-alpha');
      const hashC = hashApiKey('key-beta');

      expect(secureCompare(hashA, hashB)).toBe(true);
      expect(secureCompare(hashA, hashC)).toBe(false);
      expect(secureCompare(hashA, 'short-hash')).toBe(false);
      expect(secureCompare(null, hashA)).toBe(false);
    });

    it('should accurately detect expired keys', () => {
      const pastDate = new Date(Date.now() - 60000).toISOString();
      const futureDate = new Date(Date.now() + 60000).toISOString();

      expect(isKeyExpired({ expiresAt: pastDate })).toBe(true);
      expect(isKeyExpired({ expiresAt: futureDate })).toBe(false);
      expect(isKeyExpired({ expiresAt: null })).toBe(false);
      expect(isKeyExpired({})).toBe(false);
    });
  });

  describe('Middleware Authentication Flows', () => {
    const validKeyData = generateApiKey({ prefix: 'sag_live_' });
    const expiredKeyData = generateApiKey({ prefix: 'sag_old_' });

    function createApp(options) {
      const app = express();
      app.use(apiKeyAuth(options));
      app.get('/protected', (req, res) => {
        res.json({
          success: true,
          apiKeyInfo: req.apiKey
        });
      });
      return app;
    }

    it('should reject request when API key is completely missing with 401', async () => {
      const app = createApp({
        keys: [validKeyData.key]
      });

      const res = await request(app).get('/protected');
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
      expect(res.body.error.message).toContain('Unauthorized');
    });

    it('should accept valid key via default x-api-key header', async () => {
      const app = createApp({
        keys: [
          {
            id: 'client-abc',
            name: 'Analytics Service',
            key: validKeyData.key,
            permissions: ['read', 'write']
          }
        ]
      });

      const res = await request(app)
        .get('/protected')
        .set('x-api-key', validKeyData.key);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.apiKeyInfo).toEqual({
        id: 'client-abc',
        name: 'Analytics Service',
        permissions: ['read', 'write'],
        metadata: {}
      });
      // Crucial: plaintext key or raw hash must NEVER be attached to req.apiKey
      expect(res.body.apiKeyInfo.key).toBeUndefined();
      expect(res.body.apiKeyInfo.hash).toBeUndefined();
    });

    it('should accept valid key via Authorization: Bearer <key>', async () => {
      const app = createApp({
        keys: [validKeyData.key],
        allowBearer: true
      });

      const res = await request(app)
        .get('/protected')
        .set('Authorization', `Bearer ${validKeyData.key}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should accept valid key via Authorization: Api-Key <key>', async () => {
      const app = createApp({
        keys: [validKeyData.key],
        allowBearer: true
      });

      const res = await request(app)
        .get('/protected')
        .set('Authorization', `Api-Key ${validKeyData.key}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should support pre-hashed keys in configuration to avoid plaintext in memory', async () => {
      const app = createApp({
        keys: [
          {
            id: 'hashed-key-1',
            hash: validKeyData.hash
          }
        ]
      });

      const res = await request(app)
        .get('/protected')
        .set('x-api-key', validKeyData.key);

      expect(res.status).toBe(200);
    });

    it('should reject invalid API key with 401', async () => {
      const app = createApp({
        keys: [validKeyData.key]
      });

      const res = await request(app)
        .get('/protected')
        .set('x-api-key', 'sag_live_invalidkey12345');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject expired API key with 403 Forbidden', async () => {
      const app = createApp({
        keys: [
          {
            id: 'expired-1',
            key: expiredKeyData.key,
            expiresAt: new Date(Date.now() - 100000).toISOString()
          }
        ]
      });

      const res = await request(app)
        .get('/protected')
        .set('x-api-key', expiredKeyData.key);

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FORBIDDEN');
      expect(res.body.error.message).toContain('expired');
    });

    it('should enforce required permissions on routes', async () => {
      const app = createApp({
        keys: [
          {
            id: 'readonly-key',
            key: validKeyData.key,
            permissions: ['read:users']
          }
        ],
        requiredPermissions: ['read:users', 'write:users']
      });

      const res = await request(app)
        .get('/protected')
        .set('x-api-key', validKeyData.key);

      expect(res.status).toBe(403);
      expect(res.body.error.message).toContain('Insufficient permissions');
    });

    it('should support dynamic async getKey function for database lookup', async () => {
      const db = new Map();
      db.set(validKeyData.hash, {
        id: 'db-user-42',
        hash: validKeyData.hash,
        name: 'Enterprise Client'
      });

      const app = createApp({
        getKey: async (hash) => db.get(hash)
      });

      const res = await request(app)
        .get('/protected')
        .set('x-api-key', validKeyData.key);

      expect(res.status).toBe(200);
      expect(res.body.apiKeyInfo.id).toBe('db-user-42');
    });

    it('should support custom verifyKey function', async () => {
      const app = createApp({
        verifyKey: async (rawKey) => {
          if (rawKey === 'custom-super-secret') {
            return { id: 'custom-admin', name: 'Admin' };
          }
          return false;
        }
      });

      const validRes = await request(app)
        .get('/protected')
        .set('x-api-key', 'custom-super-secret');
      expect(validRes.status).toBe(200);

      const invalidRes = await request(app)
        .get('/protected')
        .set('x-api-key', 'wrong-key');
      expect(invalidRes.status).toBe(401);
    });

    it('should allow API key in query params only when queryParam option is explicitly set', async () => {
      // By default queryParam is null; test query param is ignored
      const defaultApp = createApp({ keys: [validKeyData.key] });
      const defaultRes = await request(defaultApp).get(`/protected?api_key=${validKeyData.key}`);
      expect(defaultRes.status).toBe(401);

      // When queryParam is configured
      const queryApp = createApp({ keys: [validKeyData.key], queryParam: 'api_key' });
      const queryRes = await request(queryApp).get(`/protected?api_key=${validKeyData.key}`);
      expect(queryRes.status).toBe(200);
    });
  });
});

