'use strict';

const express = require('express');
const request = require('supertest');
const { requestSize, parseContentLength } = require('../src');

describe('Request Size Protection Middleware', () => {
  describe('Content-Length Header Parser & HTTP Smuggling Guard', () => {
    it('should parse valid single Content-Length header', () => {
      const req = { headers: { 'content-length': '1024' } };
      const { length, error } = parseContentLength(req);
      expect(length).toBe(1024);
      expect(error).toBeNull();
    });

    it('should reject malformed non-numeric Content-Length header', () => {
      const req = { headers: { 'content-length': '1024abc' } };
      const { length, error } = parseContentLength(req);
      expect(length).toBeNull();
      expect(error).toContain('Malformed Content-Length');
    });

    it('should reject multiple conflicting Content-Length headers (HTTP smuggling prevention)', () => {
      const req = { headers: { 'content-length': '100, 200' } };
      const { length, error } = parseContentLength(req);
      expect(length).toBeNull();
      expect(error).toContain('Conflicting Content-Length');
    });

    it('should allow multiple identical Content-Length headers', () => {
      const req = { headers: { 'content-length': '150, 150' } };
      const { length, error } = parseContentLength(req);
      expect(length).toBe(150);
      expect(error).toBeNull();
    });
  });

  describe('Middleware Execution', () => {
    function createApp(sizeOptions = { maxSize: '100b' }) {
      const app = express();
      app.use(requestSize(sizeOptions));
      app.use(express.json());
      app.post('/upload', (req, res) => {
        res.json({ success: true, body: req.body });
      });
      return app;
    }

    it('should allow requests within size limit', async () => {
      const app = createApp({ maxSize: '1kb' });
      const res = await request(app)
        .post('/upload')
        .send({ message: 'Hello' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should reject requests exceeding Content-Length with 413 Payload Too Large', async () => {
      const app = createApp({ maxSize: '50b' });
      // Send large payload exceeding 50 bytes
      const largePayload = { message: 'A'.repeat(200) };

      const res = await request(app)
        .post('/upload')
        .send(largePayload);

      expect(res.status).toBe(413);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE');
      expect(res.headers.connection).toBe('close');
    });

    it('should reject requests with malformed Content-Length with 400 Bad Request', async () => {
      const app = createApp({ maxSize: '1kb' });

      const res = await request(app)
        .post('/upload')
        .set('Content-Length', 'invalid-length')
        .send('some-data');

      expect(res.status).toBe(400);
    });

    it('should reject request via middleware when Content-Length has conflicting values', () => {
      const middleware = requestSize({ maxSize: '1kb' });
      const req = { headers: { 'content-length': '100, 200' }, socket: {} };
      let sentStatus = null;
      let sentPayload = null;
      const res = {
        headersSent: false,
        status: (s) => {
          sentStatus = s;
          return {
            json: (payload) => {
              sentPayload = payload;
            }
          };
        }
      };
      const next = vi.fn();

      middleware(req, res, next);
      expect(sentStatus).toBe(400);
      expect(sentPayload.error.code).toBe('BAD_REQUEST');
      expect(next).not.toHaveBeenCalled();
    });

    it('should inspect pre-parsed bodies if placed after body-parser', async () => {
      const app = express();
      app.use(express.json());
      // Placed after express.json()
      app.use(requestSize({ maxSize: '60b' }));
      app.post('/upload', (req, res) => res.json({ success: true }));

      const res = await request(app)
        .post('/upload')
        .send({ data: 'X'.repeat(300) });

      expect(res.status).toBe(413);
      expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE');
    });
  });
});
