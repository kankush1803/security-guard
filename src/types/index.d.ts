import { Request, Response, NextFunction, RequestHandler } from 'express';

declare global {
  namespace Express {
    interface Request {
      apiKey?: {
        id: string;
        name?: string;
        permissions: string[];
        metadata: Record<string, any>;
      };
      clientIp?: string;
      validated?: {
        body?: any;
        query?: any;
        params?: any;
        headers?: any;
      };
      detectedThreats?: Array<{
        ruleId: string;
        ruleName: string;
        path: string;
        snippet: string;
        severity: string;
      }>;
      id?: string;
    }
  }
}

export interface SecurityErrorPayload {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
  };
}

export class SecurityError extends Error {
  statusCode: number;
  code: string;
  details: any;
  constructor(message: string, statusCode?: number, code?: string, details?: any);
  toJSON(): SecurityErrorPayload;
}

export class RateLimitError extends SecurityError {
  constructor(message?: string, details?: any);
}

export class AuthenticationError extends SecurityError {
  constructor(message?: string, details?: any);
}

export class ForbiddenError extends SecurityError {
  constructor(message?: string, details?: any);
}

export class PayloadTooLargeError extends SecurityError {
  constructor(message?: string, details?: any);
}

export class ValidationError extends SecurityError {
  constructor(message?: string, details?: any);
}

export class ThreatDetectedError extends SecurityError {
  constructor(message?: string, statusCode?: number, details?: any);
}

export class ConfigurationError extends SecurityError {
  constructor(message: string, details?: any);
}

// Stores
export interface RateLimitStoreRecord {
  totalHits: number;
  resetTime: Date;
}

export class MemoryStore {
  constructor(options?: { windowMs?: number; cleanupIntervalMs?: number });
  init(options: { windowMs?: number }): void;
  increment(key: string): Promise<RateLimitStoreRecord>;
  decrement(key: string): Promise<void>;
  resetKey(key: string): Promise<void>;
  resetAll(): Promise<void>;
  get(key: string): Promise<RateLimitStoreRecord | undefined>;
  shutdown(): void;
}

export class RedisStore {
  constructor(options: {
    client: any;
    prefix?: string;
    windowMs?: number;
    passOnConnectionError?: boolean;
    logger?: SecurityLogger;
  });
  init(options: { windowMs?: number }): void;
  increment(key: string): Promise<RateLimitStoreRecord>;
  decrement(key: string): Promise<void>;
  resetKey(key: string): Promise<void>;
  resetAll(): Promise<void>;
  get(key: string): Promise<RateLimitStoreRecord | undefined>;
}

// Logger
export interface SecurityLogEvent {
  timestamp: string;
  level: string;
  eventType: string;
  message: string;
  requestId: string;
  ip: string;
  method?: string;
  path?: string;
  details?: Record<string, any>;
}

export class SecurityLogger {
  constructor(options?: {
    enabled?: boolean;
    level?: 'debug' | 'info' | 'warn' | 'error' | 'silent';
    customLogger?: (event: SecurityLogEvent) => void;
    redactFields?: string[];
  });
  log(level: 'debug' | 'info' | 'warn' | 'error', eventType: string, message: string, context?: any): void;
  debug(eventType: string, message: string, context?: any): void;
  info(eventType: string, message: string, context?: any): void;
  warn(eventType: string, message: string, context?: any): void;
  error(eventType: string, message: string, context?: any): void;
}

export const defaultLogger: SecurityLogger;
export function redact(value: any, customSensitiveKeys?: string[]): any;
export function getRequestId(req: Request): string;
export const DEFAULT_SENSITIVE_KEYS: string[];

// Rate Limiter
export interface RateLimiterOptions {
  windowMs?: number;
  maxRequests?: number;
  max?: number;
  statusCode?: number;
  message?: string;
  keyGenerator?: (req: Request) => string;
  skip?: (req: Request) => boolean;
  store?: 'memory' | 'redis' | any;
  redisClient?: any;
  redisPrefix?: string;
  passOnRedisError?: boolean;
  handler?: (req: Request, res: Response, error: RateLimitError) => void;
  logger?: SecurityLogger;
  standardHeaders?: boolean | 'draft-6' | 'draft-7';
  legacyHeaders?: boolean;
}

export function rateLimiter(options?: RateLimiterOptions): RequestHandler;
export function createRateLimiter(options?: RateLimiterOptions): RequestHandler;
export function defaultKeyGenerator(req: Request): string;

// API Key Auth
export interface ApiKeyRecord {
  id?: string;
  name?: string;
  key?: string;
  hash?: string;
  expiresAt?: string | Date | number | null;
  permissions?: string[];
  metadata?: Record<string, any>;
}

export interface ApiKeyAuthOptions {
  headerName?: string;
  queryParam?: string | null;
  allowBearer?: boolean;
  hashAlgorithm?: string;
  keys?: Array<string | ApiKeyRecord>;
  getKey?: (hash: string, req: Request) => Promise<ApiKeyRecord | null | undefined>;
  verifyKey?: (rawKey: string, req: Request) => Promise<boolean | ApiKeyRecord>;
  requiredPermissions?: string[];
  statusCode?: number;
  forbiddenStatusCode?: number;
  message?: string;
  forbiddenMessage?: string;
  handler?: (req: Request, res: Response, error: SecurityError) => void;
  logger?: SecurityLogger;
}

export function apiKeyAuth(options?: ApiKeyAuthOptions): RequestHandler;
export function createApiKeyAuth(options?: ApiKeyAuthOptions): RequestHandler;
export function extractApiKey(req: Request, options: ApiKeyAuthOptions): string | null;
export function generateApiKey(options?: { prefix?: string; bytes?: number; algorithm?: string }): { key: string; hash: string; prefix: string };
export function hashApiKey(rawKey: string, algorithm?: string): string;
export function secureCompare(a: string, b: string): boolean;
export function isKeyExpired(keyRecord: any): boolean;

// IP Filter
export interface IpFilterOptions {
  mode?: 'allowlist' | 'blocklist';
  allowlist?: string[];
  blocklist?: string[];
  trustProxy?: boolean | string[] | number;
  getIp?: (req: Request) => string;
  statusCode?: number;
  message?: string;
  handler?: (req: Request, res: Response, error: ForbiddenError) => void;
  logger?: SecurityLogger;
}

export function ipFilter(options?: IpFilterOptions): RequestHandler;
export function createIpFilter(options?: IpFilterOptions): RequestHandler;
export function parseIp(ipString: string): any;
export function formatIp(ipString: string): string;
export function parseRule(ruleString: string): any;
export function matchesRule(clientIp: any, rule: any): boolean;
export function isIpInRules(clientIpStr: string, compiledRules: any[]): boolean;
export function compileRules(ruleStrings: string[]): any[];
export function getClientIp(req: Request, options?: any): string;

// Request Size
export interface RequestSizeOptions {
  maxSize?: string | number;
  statusCode?: number;
  message?: string;
  handler?: (req: Request, res: Response, error: PayloadTooLargeError) => void;
  logger?: SecurityLogger;
}

export function requestSize(options?: RequestSizeOptions): RequestHandler;
export function createRequestSize(options?: RequestSizeOptions): RequestHandler;
export function parseContentLength(req: Request): { length: number | null; error: string | null };

// Security Headers
export interface SecurityHeadersOptions {
  contentSecurityPolicy?: boolean | any;
  hsts?: boolean | any;
  frameguard?: boolean | any;
  noSniff?: boolean;
  referrerPolicy?: boolean | any;
  noIndex?: boolean;
  permissionsPolicy?: boolean | string;
  [key: string]: any;
}

export function securityHeaders(options?: SecurityHeadersOptions): RequestHandler;
export function createSecurityHeaders(options?: SecurityHeadersOptions): RequestHandler;

// Request Validator
export interface ValidationSchemas {
  body?: any;
  query?: any;
  params?: any;
  headers?: any;
}

export interface RequestValidatorOptions {
  assignToReq?: boolean;
  statusCode?: number;
  message?: string;
  handler?: (req: Request, res: Response, error: ValidationError) => void;
  logger?: SecurityLogger;
}

export function requestValidator(schemas: ValidationSchemas | any, options?: RequestValidatorOptions): RequestHandler;
export function createRequestValidator(schemas: ValidationSchemas | any, options?: RequestValidatorOptions): RequestHandler;

// Threat Detector
export interface ThreatRule {
  id: string;
  name: string;
  pattern: RegExp | ((val: any, path: string) => boolean);
  severity: 'high' | 'medium' | 'low';
}

export interface ThreatMatch {
  ruleId: string;
  ruleName: string;
  path: string;
  snippet: string;
  severity: string;
}

export interface ThreatDetectorOptions {
  action?: 'reject' | 'log' | 'pass';
  statusCode?: number;
  message?: string;
  inspectUrl?: boolean;
  inspectQuery?: boolean;
  inspectBody?: boolean;
  inspectHeaders?: boolean;
  whitelistedPaths?: Array<string | RegExp>;
  whitelistedKeys?: string[];
  customRules?: ThreatRule[];
  handler?: (req: Request, res: Response, error: ThreatDetectedError) => void;
  logger?: SecurityLogger;
}

export function threatDetector(options?: ThreatDetectorOptions): RequestHandler;
export function createThreatDetector(options?: ThreatDetectorOptions): RequestHandler;
export const DEFAULT_THREAT_PATTERNS: ThreatRule[];
export function scanValue(value: any, rules: ThreatRule[], currentPath?: string, whitelistedKeys?: string[]): ThreatMatch[];

// Helper
export function sendSecurityResponse(
  req: Request,
  res: Response,
  error: SecurityError | Error | string,
  statusCode?: number,
  customHandler?: (req: Request, res: Response, error: any) => void
): void;

