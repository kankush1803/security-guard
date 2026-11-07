'use strict';

const defaults = require('../config/defaults');
const { ValidationError } = require('../utils/errors');
const { sendSecurityResponse } = require('../utils/response');
const { defaultLogger } = require('../utils/logger');

/**
 * Formats validation issues into a clean, client-safe array of field-level errors.
 *
 * @param {Array<any>} rawIssues
 * @param {'body'|'query'|'params'|'headers'} target
 * @returns {Array<{ field: string, message: string, code?: string }>}
 */
function formatIssues(rawIssues = [], target) {
  return rawIssues.map((issue) => {
    let field = target;
    if (issue.path && issue.path.length > 0) {
      field = `${target}.${issue.path.join('.')}`;
    } else if (issue.field) {
      field = `${target}.${issue.field}`;
    }

    return {
      field,
      message: issue.message || 'Invalid value',
      code: issue.code || 'INVALID_INPUT'
    };
  });
}

/**
 * Validates a target object against a schema or validator function.
 * Supports Zod schemas, Joi-like schemas, or custom functions.
 *
 * @param {any} schema - Validation schema or function.
 * @param {any} data - Data to validate.
 * @param {'body'|'query'|'params'|'headers'} target - Target name for error messages.
 * @returns {Promise<{ success: boolean, data?: any, issues?: Array<any> }>}
 */
async function validateTarget(schema, data, target) {
  if (!schema) {
    return { success: true, data };
  }

  // 1. Custom function: (data) => boolean | { success, errors, data }
  if (typeof schema === 'function' && !schema.safeParse && !schema.parse) {
    try {
      const res = await schema(data);
      if (res === true || (res && res.success === true)) {
        return { success: true, data: res.data !== undefined ? res.data : data };
      }
      const issues = res && res.errors ? res.errors : [{ message: 'Validation rule failed' }];
      return { success: false, issues: formatIssues(issues, target) };
    } catch (err) {
      return { success: false, issues: [{ field: target, message: err.message, code: 'VALIDATION_ERROR' }] };
    }
  }

  // 2. Zod schema: safeParseAsync or safeParse
  if (typeof schema.safeParseAsync === 'function') {
    const result = await schema.safeParseAsync(data);
    if (result.success) {
      return { success: true, data: result.data };
    }
    return { success: false, issues: formatIssues(result.error.issues, target) };
  }

  if (typeof schema.safeParse === 'function') {
    const result = schema.safeParse(data);
    if (result.success) {
      return { success: true, data: result.data };
    }
    return { success: false, issues: formatIssues(result.error.issues, target) };
  }

  // 3. Fallback for schema with parse() method
  if (typeof schema.parse === 'function') {
    try {
      const parsedData = schema.parse(data);
      return { success: true, data: parsedData };
    } catch (err) {
      const issues = err.issues || [{ message: err.message }];
      return { success: false, issues: formatIssues(issues, target) };
    }
  }

  throw new Error(`Unsupported schema format for ${target}. Must be a Zod schema or validator function.`);
}

/**
 * Creates request validation middleware.
 *
 * @param {Object} schemas - Validation schemas.
 * @param {any} [schemas.body] - Schema for req.body.
 * @param {any} [schemas.query] - Schema for req.query.
 * @param {any} [schemas.params] - Schema for req.params.
 * @param {any} [schemas.headers] - Schema for req.headers.
 * @param {Object} [userOptions]
 * @param {boolean} [userOptions.assignToReq=false] - Whether to mutate req.body/req.query with parsed data (default false: store in req.validated).
 * @param {number} [userOptions.statusCode=400] - Status code on failure.
 * @param {string} [userOptions.message] - Custom error message.
 * @param {Function} [userOptions.handler] - Custom error handler.
 * @param {import('../utils/logger').SecurityLogger} [userOptions.logger] - Logger instance.
 * @returns {import('express').RequestHandler}
 */
function createRequestValidator(schemas = {}, userOptions = {}) {
  // If user passed a single Zod schema directly as first arg
  let targetSchemas = schemas;
  if (schemas && (typeof schemas.safeParse === 'function' || typeof schemas.safeParseAsync === 'function')) {
    targetSchemas = { body: schemas };
  }

  const options = {
    ...defaults.requestValidator,
    ...userOptions
  };

  const logger = options.logger || defaultLogger;

  return async function requestValidatorMiddleware(req, res, next) {
    const targets = ['body', 'query', 'params', 'headers'];
    const allIssues = [];
    const validatedData = {};

    for (const target of targets) {
      const schema = targetSchemas[target];
      if (schema) {
        const dataToValidate = req[target] || {};
        const result = await validateTarget(schema, dataToValidate, target);

        if (!result.success) {
          allIssues.push(...result.issues);
        } else {
          validatedData[target] = result.data;
          if (options.assignToReq) {
            req[target] = result.data;
          }
        }
      }
    }

    if (allIssues.length > 0) {
      logger.warn('REQUEST_VALIDATION_FAILED', `Validation failed for ${req.method} ${req.path}`, {
        req,
        details: { issues: allIssues }
      });

      const error = new ValidationError(options.message, { issues: allIssues });
      return sendSecurityResponse(req, res, error, options.statusCode, options.handler);
    }

    // Attach validated data securely to req.validated
    req.validated = {
      ...req.validated,
      ...validatedData
    };

    return next();
  };
}

module.exports = {
  requestValidator: createRequestValidator,
  createRequestValidator,
  formatIssues
};

