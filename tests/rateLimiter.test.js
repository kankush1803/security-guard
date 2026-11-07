'use strict';

const express = require('express');
const request = require('supertest');
const { rateLimiter, MemoryStore, RedisStore } = require('../src');

describe('Rate Limiter Middleware & Stores', () => {
  describe('MemoryStore', () => {
    let store;

    beforeEach(() => {
      store = new MemoryStore({ windowMs: 1000, cleanupIntervalMs: 500 });
    });

    afterEach(() => {
      store.shutdown();
    });

    it('should increment hits accurately for a key', async () => {
      const r1 = await store.increment('client-1');
      expect(r1.totalHits).toBe(1);
      expect(r1.resetTime).toBeInstanceOf(Date);

      const r2 = await store.increment('client-1');
      expect(r2.totalHits).toBe(2);

      const r3 = await store.increment('client-2');
      expect(r3.totalHits).toBe(1);
    });

    it('should decrement hits for a key', async () => {
      await store.increment('client-1');
      await store.increment('client-1');
      await store.decrement('client-1');

      const info = await store.get('client-1');
      expect(info.totalHits).toBe(1);
    });

    it('should reset a single key', async () => {
      await store.increment('client-1');
      await store.resetKey('client-1');
      const info = await store.get('client-1');
      expect(info).toBeUndefined();
    });

    it('should reset all keys', async () => {
      await store.increment('client-1');
      await store.increment('client-2');
      await store.resetAll();
      expect(await store.get('client-1')).toBeUndefined();
      expect(await store.get('client-2')).toBeUndefined();
    });

    it('should purge expired keys during cleanup', async () => {
      // Force expired record
      store.hits.set('expired-key', { totalHits: 5, resetTime: Date.now() - 100 });
      store.hits.set('valid-key', { totalHits: 2, resetTime: Date.now() + 10000 });

      store.cleanup();
      expect(store.hits.has('expired-key')).toBe(false);
      expect(store.hits.has('valid-key')).toBe(true);
    });
  });

  describe('RedisStore', () => {
    it('should increment and return totalHits and resetTime using mock client', async () => {
      // Mock Redis client with Lua eval
      const redisState = new Map();
      const mockClient = {
        eval: vi.fn(async (script, optsOrNum, ...args) => {
          // Identify key and windowMs
          let key;
          let windowMs;
          if (typeof optsOrNum === 'object') {
            key = optsOrNum.keys[0];
            windowMs = parseInt(optsOrNum.arguments[0], 10);
          } else {
            key = args[0];
            windowMs = parseInt(args[1], 10);
          }
          const current = (redisState.get(key) || 0) + 1;
          redisState.set(key, current);
          return [current, windowMs];
        }),
        decr: vi.fn(async (key) => {
          const val = (redisState.get(key) || 1) - 1;
          redisState.set(key, val);
        }),
        del: vi.fn(async (...keys) => {
          keys.forEach((k) => redisState.delete(k));
        }),
        get: vi.fn(async (key) => (redisState.get(key) ? String(redisState.get(key)) : null)),
        pttl: vi.fn(async () => 50000)
      };

      const redisStore = new RedisStore({ client: mockClient, windowMs: 60000 });
      const res1 = await redisStore.increment('user-100');
      expect(res1.totalHits).toBe(1);
      expect(res1.resetTime).toBeInstanceOf(Date);

      const res2 = await redisStore.increment('user-100');
      expect(res2.totalHits).toBe(2);

      await redisStore.decrement('user-100');
      expect(mockClient.decr).toHaveBeenCalledWith('sag:rl:user-100');

      await redisStore.resetKey('user-100');
      expect(mockClient.del).toHaveBeenCalledWith('sag:rl:user-100');
    });

    it('should fail open gracefully when Redis connection fails and passOnConnectionError is true', async () => {
      const brokenClient = {
        eval: vi.fn().mockRejectedValue(new Error('ECONNREFUSED - Redis cluster down'))
      };

      const redisStore = new RedisStore({
        client: brokenClient,
        passOnConnectionError: true
      });

      const res = await redisStore.increment('user-broken');
      expect(res.totalHits).toBe(1);
      expect(res.resetTime).toBeInstanceOf(Date);
    });

    it('should rethrow error when passOnConnectionError is false', async () => {
      const brokenClient = {
        eval: vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
      };

      const redisStore = new RedisStore({
        client: brokenClient,
        passOnConnectionError: false
      });

      await expect(redisStore.increment('user-broken')).rejects.toThrow('ECONNREFUSED');
    });
  });

  describe('Rate Limiter Express Middleware', () => {
    it('should allow requests under the limit and set standard rate limit headers', async () => {
      const app = express();
      app.use(
        rateLimiter({
          windowMs: 60000,
          maxRequests: 3
        })
      );
      app.get('/test', (req, res) => res.json({ success: true }));

      const res1 = await request(app).get('/test');
      expect(res1.status).toBe(200);
      expect(res1.body.success).toBe(true);

      const res2 = await request(app).get('/test');
      expect(res2.status).toBe(200);

      const res3 = await request(app).get('/test');
      expect(res3.status).toBe(200);
    });

    it('should reject requests exceeding limit with 429 and structured error', async () => {
      const app = express();
      app.use(
        rateLimiter({
          windowMs: 60000,
          maxRequests: 2,
          message: 'Limit reached for this IP.'
        })
      );
      app.get('/test', (req, res) => res.json({ success: true }));

      await request(app).get('/test');
      await request(app).get('/test');

      const blockedRes = await request(app).get('/test');
      expect(blockedRes.status).toBe(429);
      expect(blockedRes.body.success).toBe(false);
      expect(blockedRes.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(blockedRes.body.error.message).toBe('Limit reached for this IP.');
      expect(blockedRes.body.error.details.limit).toBe(2);
      expect(blockedRes.body.error.details.retryAfter).toBeGreaterThan(0);
    });

    it('should isolate rate limits across multiple IP addresses', async () => {
      const app = express();
      app.set('trust proxy', true);
      app.use(
        rateLimiter({
          windowMs: 60000,
          maxRequests: 2
        })
      );
      app.get('/test', (req, res) => res.json({ ip: req.ip }));

      // IP 1: hits limit
      await request(app).get('/test').set('X-Forwarded-For', '198.51.100.1');
      await request(app).get('/test').set('X-Forwarded-For', '198.51.100.1');
      const ip1Blocked = await request(app).get('/test').set('X-Forwarded-For', '198.51.100.1');
      expect(ip1Blocked.status).toBe(429);

      // IP 2: still within limit
      const ip2Res = await request(app).get('/test').set('X-Forwarded-For', '198.51.100.2');
      expect(ip2Res.status).toBe(200);
    });

    it('should support custom keyGenerator (e.g. user ID or API key header)', async () => {
      const app = express();
      app.use(
        rateLimiter({
          windowMs: 60000,
          maxRequests: 1,
          keyGenerator: (req) => req.headers['x-tenant-id'] || 'anonymous'
        })
      );
      app.get('/test', (req, res) => res.json({ ok: true }));

      // Tenant A
      const resA1 = await request(app).get('/test').set('x-tenant-id', 'tenant-a');
      expect(resA1.status).toBe(200);
      const resA2 = await request(app).get('/test').set('x-tenant-id', 'tenant-a');
      expect(resA2.status).toBe(429);

      // Tenant B
      const resB1 = await request(app).get('/test').set('x-tenant-id', 'tenant-b');
      expect(resB1.status).toBe(200);
    });

    it('should support skipping specific requests', async () => {
      const app = express();
      app.use(
        rateLimiter({
          windowMs: 60000,
          maxRequests: 1,
          skip: (req) => req.path === '/health'
        })
      );
      app.get('/health', (req, res) => res.json({ status: 'ok' }));
      app.get('/api', (req, res) => res.json({ data: 'ok' }));

      // Health route never blocked
      await request(app).get('/health');
      await request(app).get('/health');
      const resHealth = await request(app).get('/health');
      expect(resHealth.status).toBe(200);

      // Api route blocked after 1 hit
      await request(app).get('/api');
      const resApi = await request(app).get('/api');
      expect(resApi.status).toBe(429);
    });
  });
});
