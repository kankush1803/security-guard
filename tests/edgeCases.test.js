'use strict';

const express = require('express');
const request = require('supertest');
const {
  rateLimiter,
  apiKeyAuth,
  ipFilter,
  threatDetector,
  requestValidator,
  sendSecurityResponse,
  validateConfig,
  RedisStore,
  MemoryStore,
  getClientIp,
  parseIp,
  parseRule,
  matchesRule
} = require('../src');

describe('Security Edge Cases & Auxiliary Branch Coverage', () => {
  describe('sendSecurityResponse Edge Cases', () => {
    it('should invoke customHandler when provided', () => {
      const customHandler = vi.fn((req, res, err) => {
        res.status(418).json({ custom: true, message: err.message });
      });
      const req = {};
      let sentStatus;
      let sentBody;
      const res = {
        headersSent: false,
        status: (s) => {
          sentStatus = s;
          return { json: (b) => { sentBody = b; } };
        }
      };

      sendSecurityResponse(req, res, new Error('teapot'), 418, customHandler);
      expect(customHandler).toHaveBeenCalled();
    });

    it('should ignore response if headersSent is already true', () => {
      const res = { headersSent: true, status: vi.fn() };
      sendSecurityResponse({}, res, new Error('already sent'));
      expect(res.status).not.toHaveBeenCalled();
    });

    it('should handle string errors and generic Error instances', () => {
      let sentStatus;
      let sentBody;
      const res = {
        headersSent: false,
        status: (s) => {
          sentStatus = s;
          return { json: (b) => { sentBody = b; } };
        }
      };

      // String error
      sendSecurityResponse({}, res, 'Plain text rejection');
      expect(sentStatus).toBe(400);
      expect(sentBody.error.message).toBe('Plain text rejection');

      // Generic error
      sendSecurityResponse({}, res, new Error('Server blew up'));
      expect(sentStatus).toBe(500);
      expect(sentBody.error.message).toBe('Server blew up');
    });
  });

  describe('Configuration Validation Edge Cases', () => {
    it('should validate all config rules strictly', () => {
      expect(() => validateConfig.validateRateLimiterConfig({ statusCode: 999 })).toThrow();
      expect(() => validateConfig.validateRateLimiterConfig({ keyGenerator: 'invalid' })).toThrow();
      expect(() => validateConfig.validateRateLimiterConfig({ skip: 'invalid' })).toThrow();

      expect(() => validateConfig.validateApiKeyAuthConfig({ queryParam: '' })).toThrow();
      expect(() => validateConfig.validateApiKeyAuthConfig({ verifyKey: 'invalid' })).toThrow();
      expect(() => validateConfig.validateApiKeyAuthConfig({ keys: 'not-array-or-obj' })).toThrow();

      expect(() => validateConfig.validateIpFilterConfig({ blocklist: 'not-array' })).toThrow();
      expect(() => validateConfig.validateIpFilterConfig({ getIp: 'not-fn' })).toThrow();

      expect(() => validateConfig.validateRequestSizeConfig({ maxSize: -50 })).toThrow();
      expect(() => validateConfig.validateRequestSizeConfig({ maxSize: {} })).toThrow();

      expect(() => validateConfig.validateThreatDetectorConfig({ action: 'invalid-action' })).toThrow();
      expect(() => validateConfig.validateThreatDetectorConfig({ customRules: 'not-array' })).toThrow();
      expect(() => validateConfig.validateThreatDetectorConfig({ whitelistedPaths: 'not-array' })).toThrow();
    });
  });

  describe('Rate Limiter Redis Option Integration', () => {
    it('should initialize RedisStore when store is "redis" and redisClient is passed', async () => {
      const mockClient = {
        eval: vi.fn().mockResolvedValue([1, 60000]),
        decr: vi.fn(),
        del: vi.fn()
      };

      const limiter = rateLimiter({
        store: 'redis',
        redisClient: mockClient,
        windowMs: 60000,
        maxRequests: 5
      });

      const app = express();
      app.use(limiter);
      app.get('/redis-test', (req, res) => res.json({ ok: true }));

      const res = await request(app).get('/redis-test');
      expect(res.status).toBe(200);
      expect(mockClient.eval).toHaveBeenCalled();
    });

    it('should throw if store is "redis" but redisClient is missing', () => {
      expect(() => rateLimiter({ store: 'redis' })).toThrow();
    });
  });

  describe('RedisStore Auxiliary Methods (get, resetAll)', () => {
    it('should execute get and resetAll on RedisStore', async () => {
      const mockClient = {
        get: vi.fn().mockResolvedValue('5'),
        pttl: vi.fn().mockResolvedValue('30000'),
        keys: vi.fn().mockResolvedValue(['sag:rl:1', 'sag:rl:2']),
        del: vi.fn().mockResolvedValue(2)
      };

      const store = new RedisStore({ client: mockClient });
      const record = await store.get('client-key');
      expect(record.totalHits).toBe(5);

      await store.resetAll();
      expect(mockClient.keys).toHaveBeenCalled();
      expect(mockClient.del).toHaveBeenCalledWith('sag:rl:1', 'sag:rl:2');
    });
  });

  describe('IP Extraction & Proxy Hops', () => {
    it('should support numeric proxy hop count', () => {
      const req = {
        headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3' },
        socket: { remoteAddress: '127.0.0.1' }
      };

      // trust 1 hop from the right
      const ip = getClientIp(req, { trustProxy: 1 });
      expect(ip).toBe('3.3.3.3');

      // trust 2 hops from the right
      const ip2 = getClientIp(req, { trustProxy: 2 });
      expect(ip2).toBe('2.2.2.2');
    });

    it('should support custom function in getIp', () => {
      const req = { customClientIp: '192.168.10.15' };
      const ip = getClientIp(req, { getIp: (r) => r.customClientIp });
      expect(ip).toBe('192.168.10.15');
    });
  });

  describe('Threat Detector Additional Scenarios', () => {
    it('should pass through when action is "pass"', async () => {
      const app = express();
      app.use(threatDetector({ action: 'pass' }));
      app.get('/pass-test', (req, res) => res.json({ ok: true }));

      const res = await request(app).get('/pass-test?q=../../etc/passwd');
      expect(res.status).toBe(200);
    });

    it('should scan headers when inspectHeaders is true', async () => {
      const app = express();
      app.use(threatDetector({ action: 'reject', inspectHeaders: true }));
      app.get('/headers-test', (req, res) => res.json({ ok: true }));

      const res = await request(app)
        .get('/headers-test')
        .set('x-custom-header', '../../etc/shadow');

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('THREAT_DETECTED');
    });

    it('should support function patterns in custom rules', async () => {
      const app = express();
      app.use(
        threatDetector({
          action: 'reject',
          customRules: [
            {
              id: 'DETECT_EVIL',
              name: 'Detect evil keyword',
              pattern: (val) => typeof val === 'string' && val.includes('super-evil-string'),
              severity: 'high'
            }
          ]
        })
      );
      app.get('/fn-rule', (req, res) => res.json({ ok: true }));

      const res = await request(app).get('/fn-rule?payload=super-evil-string');
      expect(res.status).toBe(403);
      expect(res.body.error.details.threats[0].ruleId).toBe('DETECT_EVIL');
    });
  });

  describe('Request Validator Schema Varieties', () => {
    it('should support schemas with .parse() method', async () => {
      const schemaWithParse = {
        parse: (data) => {
          if (!data.id) throw new Error('Missing ID');
          return data;
        }
      };

      const app = express();
      app.use(express.json());
      app.post('/parse-test', requestValidator({ body: schemaWithParse }), (req, res) => {
        res.json({ ok: true, validated: req.validated });
      });

      const resFail = await request(app).post('/parse-test').send({});
      expect(resFail.status).toBe(400);

      const resPass = await request(app).post('/parse-test').send({ id: 123 });
      expect(resPass.status).toBe(200);
    });
  });
});

