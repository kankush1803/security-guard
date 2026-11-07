'use strict';

const express = require('express');
const request = require('supertest');
const { z } = require('zod');
const { requestValidator } = require('../src');

describe('Request Validation Middleware (Zod & Custom Integration)', () => {
  describe('Zod Schema Validation', () => {
    const userSchema = z.object({
      username: z.string().min(3).max(20),
      email: z.string().email(),
      age: z.number().int().positive().optional()
    });

    const querySchema = z.object({
      page: z.string().regex(/^\d+$/).transform(Number),
      limit: z.string().regex(/^\d+$/).transform(Number).optional()
    });

    function createApp() {
      const app = express();
      app.use(express.json());
      app.post(
        '/users',
        requestValidator({
          body: userSchema,
          query: querySchema
        }),
        (req, res) => {
          res.json({
            success: true,
            validated: req.validated,
            rawBody: req.body
          });
        }
      );
      return app;
    }

    it('should allow valid requests and attach parsed data to req.validated', async () => {
      const app = createApp();

      const res = await request(app)
        .post('/users?page=1&limit=10')
        .send({
          username: 'johndoe',
          email: 'john@example.com',
          age: 30
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.validated.body).toEqual({
        username: 'johndoe',
        email: 'john@example.com',
        age: 30
      });
      expect(res.body.validated.query.page).toBe(1);
    });

    it('should reject invalid body with 400 Bad Request and structured issues', async () => {
      const app = createApp();

      const res = await request(app)
        .post('/users?page=1')
        .send({
          username: 'jo', // too short (< 3)
          email: 'not-an-email'
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(Array.isArray(res.body.error.details.issues)).toBe(true);
      expect(res.body.error.details.issues.length).toBeGreaterThanOrEqual(2);

      const fields = res.body.error.details.issues.map((i) => i.field);
      expect(fields).toContain('body.username');
      expect(fields).toContain('body.email');
    });

    it('should reject invalid query parameters with 400', async () => {
      const app = createApp();

      const res = await request(app)
        .post('/users?page=abc') // non-numeric page
        .send({
          username: 'johndoe',
          email: 'john@example.com'
        });

      expect(res.status).toBe(400);
      expect(res.body.error.details.issues[0].field).toBe('query.page');
    });

    it('should avoid silently modifying raw req.body by default', async () => {
      const app = createApp();

      const res = await request(app)
        .post('/users?page=2')
        .send({
          username: 'alice123',
          email: 'alice@example.com',
          extraProperty: 'should not be removed from raw body'
        });

      expect(res.status).toBe(200);
      // Raw req.body retains extraProperty
      expect(res.body.rawBody.extraProperty).toBe('should not be removed from raw body');
    });
  });

  describe('Custom Validator Functions', () => {
    it('should support custom validator functions when Zod is not used', async () => {
      const app = express();
      app.use(express.json());

      const customValidator = (body) => {
        if (!body.title || body.title.length < 5) {
          return {
            success: false,
            errors: [{ field: 'title', message: 'Title must have at least 5 chars' }]
          };
        }
        return { success: true, data: body };
      };

      app.post(
        '/articles',
        requestValidator({ body: customValidator }),
        (req, res) => res.json({ success: true, validated: req.validated })
      );

      // Invalid
      const resBad = await request(app)
        .post('/articles')
        .send({ title: 'Hi' });
      expect(resBad.status).toBe(400);
      expect(resBad.body.error.details.issues[0].field).toBe('body.title');

      // Valid
      const resGood = await request(app)
        .post('/articles')
        .send({ title: 'A Good Long Title' });
      expect(resGood.status).toBe(200);
      expect(resGood.body.validated.body.title).toBe('A Good Long Title');
    });
  });
});

