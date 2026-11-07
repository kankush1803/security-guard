'use strict';

const {
  SecurityError,
  RateLimitError,
  AuthenticationError,
  ForbiddenError,
  PayloadTooLargeError,
  ValidationError,
  ThreatDetectedError,
  ConfigurationError,
  SecurityLogger,
  redact,
  getRequestId,
  validateConfig
} = require('../src');

describe('Security Logger, Redaction & Errors', () => {
  describe('Error Classes', () => {
    it('should instantiate error classes with correct default status codes and codes', () => {
      const rateLimitErr = new RateLimitError();
      expect(rateLimitErr.statusCode).toBe(429);
      expect(rateLimitErr.code).toBe('RATE_LIMIT_EXCEEDED');

      const authErr = new AuthenticationError();
      expect(authErr.statusCode).toBe(401);
      expect(authErr.code).toBe('UNAUTHORIZED');

      const forbidErr = new ForbiddenError();
      expect(forbidErr.statusCode).toBe(403);
      expect(forbidErr.code).toBe('FORBIDDEN');

      const sizeErr = new PayloadTooLargeError();
      expect(sizeErr.statusCode).toBe(413);
      expect(sizeErr.code).toBe('PAYLOAD_TOO_LARGE');

      const valErr = new ValidationError();
      expect(valErr.statusCode).toBe(400);
      expect(valErr.code).toBe('VALIDATION_ERROR');

      const threatErr = new ThreatDetectedError();
      expect(threatErr.statusCode).toBe(403);
      expect(threatErr.code).toBe('THREAT_DETECTED');

      const configErr = new ConfigurationError('Invalid opt');
      expect(configErr.statusCode).toBe(500);
      expect(configErr.code).toBe('CONFIGURATION_ERROR');
    });

    it('should serialize error to clean JSON format without leaking internal stack traces', () => {
      const err = new SecurityError('Test rejection', 403, 'TEST_CODE', { reason: 'policy' });
      const json = err.toJSON();

      expect(json).toEqual({
        success: false,
        error: {
          code: 'TEST_CODE',
          message: 'Test rejection',
          details: { reason: 'policy' }
        }
      });
      expect(json.stack).toBeUndefined();
    });
  });

  describe('Sensitive Field Redaction', () => {
    it('should deeply redact sensitive keys in nested objects and arrays', () => {
      const sensitiveData = {
        user: 'alice',
        password: 'SuperSecretPassword123!',
        apiKey: 'sag_live_xyz987',
        credentials: {
          token: 'jwt-access-token-999',
          refreshToken: 'jwt-refresh-token-888',
          secretAnswer: 'mother-maiden-name'
        },
        tokensList: [
          { token: 'tok_1' },
          { safeName: 'device_1' }
        ],
        publicInfo: 'safe to log'
      };

      const sanitized = redact(sensitiveData);

      expect(sanitized.password).toBe('[REDACTED]');
      expect(sanitized.apiKey).toBe('[REDACTED]');
      expect(sanitized.credentials.token).toBe('[REDACTED]');
      expect(sanitized.credentials.refreshToken).toBe('[REDACTED]');
      expect(sanitized.credentials.secretAnswer).toBe('[REDACTED]');
      expect(sanitized.tokensList[0].token).toBe('[REDACTED]');
      expect(sanitized.tokensList[1].safeName).toBe('device_1');
      expect(sanitized.publicInfo).toBe('safe to log');
    });

    it('should handle circular references safely without throwing', () => {
      const objA = { name: 'A' };
      const objB = { name: 'B', parent: objA };
      objA.child = objB;

      const sanitized = redact(objA);
      expect(sanitized.name).toBe('A');
      expect(sanitized.child.name).toBe('B');
      expect(sanitized.child.parent).toBe('[Circular]');
    });

    it('should support custom sensitive keys to redact', () => {
      const data = { internalPassportNumber: 'AB1234567', name: 'Bob' };
      const sanitized = redact(data, ['passport']);
      expect(sanitized.internalPassportNumber).toBe('[REDACTED]');
      expect(sanitized.name).toBe('Bob');
    });
  });

  describe('Request ID & Security Logger', () => {
    it('should retrieve existing X-Request-Id or generate a unique random ID', () => {
      const reqWithHeader = { headers: { 'x-request-id': 'custom-req-id-123' } };
      expect(getRequestId(reqWithHeader)).toBe('custom-req-id-123');

      const reqWithoutHeader = { headers: {} };
      const generatedId = getRequestId(reqWithoutHeader);
      expect(typeof generatedId).toBe('string');
      expect(generatedId.length).toBeGreaterThan(10);
      expect(reqWithoutHeader.id).toBe(generatedId);
    });

    it('should invoke custom logger function with structured event data', () => {
      const events = [];
      const logger = new SecurityLogger({
        level: 'info',
        customLogger: (event) => events.push(event)
      });

      logger.info('TEST_EVENT', 'Security check passed', {
        ip: '10.0.0.1',
        details: { rule: 'allowlist', password: 'secretpassword' }
      });

      expect(events.length).toBe(1);
      const ev = events[0];
      expect(ev.eventType).toBe('TEST_EVENT');
      expect(ev.level).toBe('INFO');
      expect(ev.message).toBe('Security check passed');
      expect(ev.ip).toBe('10.0.0.1');
      expect(ev.details.rule).toBe('allowlist');
      // Redaction check inside logger
      expect(ev.details.password).toBe('[REDACTED]');
    });
  });

  describe('Configuration Validation', () => {
    it('should throw ConfigurationError on invalid rateLimiter options', () => {
      expect(() => validateConfig.validateRateLimiterConfig({ windowMs: -100 })).toThrow(ConfigurationError);
      expect(() => validateConfig.validateRateLimiterConfig({ maxRequests: 'not-a-number' })).toThrow(ConfigurationError);
    });

    it('should throw ConfigurationError on invalid apiKeyAuth options', () => {
      expect(() => validateConfig.validateApiKeyAuthConfig({ headerName: '' })).toThrow(ConfigurationError);
      expect(() => validateConfig.validateApiKeyAuthConfig({ getKey: 'not-a-fn' })).toThrow(ConfigurationError);
    });

    it('should throw ConfigurationError on invalid ipFilter options', () => {
      expect(() => validateConfig.validateIpFilterConfig({ mode: 'invalid-mode' })).toThrow(ConfigurationError);
      expect(() => validateConfig.validateIpFilterConfig({ allowlist: 'not-an-array' })).toThrow(ConfigurationError);
    });

    it('should throw ConfigurationError on invalid requestSize options', () => {
      expect(() => validateConfig.validateRequestSizeConfig({ maxSize: 'invalid-bytes-xyz' })).toThrow(ConfigurationError);
    });
  });
});

