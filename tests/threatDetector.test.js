'use strict';

const express = require('express');
const request = require('supertest');
const { threatDetector, scanValue, DEFAULT_THREAT_PATTERNS } = require('../src');

describe('Threat Detection Middleware', () => {
  describe('Heuristic Threat Scanner', () => {
    it('should detect path traversal attacks', () => {
      const match = scanValue('../../etc/passwd', DEFAULT_THREAT_PATTERNS);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].ruleId).toBe('PATH_TRAVERSAL');
    });

    it('should detect URL-encoded path traversal attacks', () => {
      const match = scanValue('%2e%2e%2f%2e%2e%2fetc%2fshadow', DEFAULT_THREAT_PATTERNS);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].ruleId).toBe('PATH_TRAVERSAL');
    });

    it('should detect shell command injection sequences', () => {
      const match = scanValue('input; cat /etc/passwd', DEFAULT_THREAT_PATTERNS);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].ruleId).toBe('COMMAND_INJECTION');
    });

    it('should detect suspicious script tags', () => {
      const match = scanValue('<script>alert("XSS")</script>', DEFAULT_THREAT_PATTERNS);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].ruleId).toBe('SCRIPT_TAG_INJECTION');
    });

    it('should detect prototype pollution attacks in object keys', () => {
      const payload = JSON.parse('{"__proto__": {"admin": true}}');
      const match = scanValue(payload, DEFAULT_THREAT_PATTERNS);
      expect(match.length).toBeGreaterThan(0);
      expect(match[0].ruleId).toBe('PROTOTYPE_POLLUTION');
    });
  });

  describe('Middleware Threat Blocking & Actions', () => {
    function createApp(detectorOptions = {}) {
      const app = express();
      app.use(express.json());
      app.use(threatDetector(detectorOptions));
      app.all('/data', (req, res) => {
        res.json({
          success: true,
          detectedThreats: req.detectedThreats || null
        });
      });
      return app;
    }

    it('should reject path traversal in query strings when action is "reject"', async () => {
      const app = createApp({ action: 'reject' });

      const res = await request(app).get('/data?file=../../../../etc/passwd');
      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('THREAT_DETECTED');
      expect(res.body.error.message).toContain('Suspicious request pattern detected');
    });

    it('should reject command injection in JSON request body', async () => {
      const app = createApp({ action: 'reject' });

      const res = await request(app)
        .post('/data')
        .send({
          command: 'ping 127.0.0.1; cat /etc/shadow'
        });

      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('THREAT_DETECTED');
    });

    it('should allow legitimate requests without suspicious signatures', async () => {
      const app = createApp();

      const res = await request(app)
        .post('/data?category=electronics')
        .send({
          title: 'Laptop Pro 16-inch',
          description: 'A powerful laptop with 32GB RAM and 1TB SSD.'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should log threats but allow requests through when action is "log"', async () => {
      const app = createApp({ action: 'log' });

      const res = await request(app)
        .post('/data')
        .send({ payload: '<script>evil()</script>' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.detectedThreats).toBeDefined();
      expect(res.body.detectedThreats.length).toBeGreaterThan(0);
    });

    it('should bypass threat inspection for whitelisted paths', async () => {
      const app = express();
      app.use(express.json());
      app.use(
        threatDetector({
          action: 'reject',
          whitelistedPaths: ['/webhooks/incoming', /^\/raw-content\//]
        })
      );
      app.post('/webhooks/incoming', (req, res) => res.json({ success: true }));
      app.post('/raw-content/edit', (req, res) => res.json({ success: true }));

      const res1 = await request(app)
        .post('/webhooks/incoming')
        .send({ raw: 'some; cat file' });
      expect(res1.status).toBe(200);

      const res2 = await request(app)
        .post('/raw-content/edit')
        .send({ snippet: '<script>test</script>' });
      expect(res2.status).toBe(200);
    });

    it('should bypass inspection for whitelisted field keys (avoid false positives on rich text)', async () => {
      const app = createApp({
        action: 'reject',
        whitelistedKeys: ['markdown', 'articleBody']
      });

      const res = await request(app)
        .post('/data')
        .send({
          title: 'How to use shell commands in tutorials',
          markdown: 'To view contents, use `; cat /etc/hosts` in your shell.',
          safeField: 'Regular text'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should support custom detection rules', async () => {
      const app = createApp({
        action: 'reject',
        customRules: [
          {
            id: 'CUSTOM_BITCOIN_MINER',
            name: 'Cryptominer signature',
            pattern: /stratum\+tcp:\/\//i,
            severity: 'high'
          }
        ]
      });

      const res = await request(app)
        .post('/data')
        .send({ config: 'stratum+tcp://pool.minexmr.com:4444' });

      expect(res.status).toBe(403);
      expect(res.body.error.details.threats[0].ruleId).toBe('CUSTOM_BITCOIN_MINER');
    });
  });
});
