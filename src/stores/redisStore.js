'use strict';

const { defaultLogger } = require('../utils/logger');

const LUA_INCR_SCRIPT = `
local key = KEYS[1]
local windowMs = tonumber(ARGV[1])
local current = redis.call('INCR', key)
if current == 1 then
  redis.call('PEXPIRE', key, windowMs)
end
local ttl = redis.call('PTTL', key)
if ttl < 0 then
  redis.call('PEXPIRE', key, windowMs)
  ttl = windowMs
end
return { current, ttl }
`;

/**
 * Distributed Redis store for rate limiting across multiple instances.
 */
class RedisStore {
  /**
   * @param {Object} options
   * @param {any} options.client - Redis client (ioredis or node-redis v4+).
   * @param {string} [options.prefix='sag:rl:'] - Key prefix for rate limiting.
   * @param {number} [options.windowMs=60000] - Rate limit window in milliseconds.
   * @param {boolean} [options.passOnConnectionError=true] - If Redis fails, fail open to avoid taking down API.
   * @param {import('../utils/logger').SecurityLogger} [options.logger] - Logger instance.
   */
  constructor(options = {}) {
    if (!options.client) {
      throw new Error('RedisStore requires a "client" instance (ioredis or redis).');
    }

    this.client = options.client;
    this.prefix = options.prefix || 'sag:rl:';
    this.windowMs = options.windowMs || 60000;
    this.passOnConnectionError = options.passOnConnectionError !== false;
    this.logger = options.logger || defaultLogger;
    this._evalMode = null;
  }

  /**
   * Called by express-rate-limit with middleware options.
   * @param {Object} options
   */
  init(options) {
    if (options && options.windowMs) {
      this.windowMs = options.windowMs;
    }
  }

  /**
   * Prefix a rate limit key.
   * @param {string} key
   * @returns {string}
   */
  _prefixKey(key) {
    return `${this.prefix}${key}`;
  }

  /**
   * Execute Lua script across ioredis or node-redis v4+.
   *
   * @param {string} key
   * @param {number} windowMs
   * @returns {Promise<[number, number]>} [currentHits, ttlMs]
   */
  async _evalLua(key, windowMs) {
    const fullKey = this._prefixKey(key);

    if (typeof this.client.eval !== 'function') {
      throw new Error('Provided Redis client does not support eval command.');
    }

    if (this._evalMode === 'node-redis') {
      return this.client.eval(LUA_INCR_SCRIPT, { keys: [fullKey], arguments: [String(windowMs)] });
    }
    if (this._evalMode === 'ioredis') {
      return this.client.eval(LUA_INCR_SCRIPT, 1, fullKey, String(windowMs));
    }

    // Auto-detect client signature on first execution
    try {
      const res = await this.client.eval(LUA_INCR_SCRIPT, {
        keys: [fullKey],
        arguments: [String(windowMs)]
      });
      this._evalMode = 'node-redis';
      return res;
    } catch {
      const res = await this.client.eval(LUA_INCR_SCRIPT, 1, fullKey, String(windowMs));
      this._evalMode = 'ioredis';
      return res;
    }
  }

  /**
   * Increment hits for a key.
   *
   * @param {string} key
   * @returns {Promise<{ totalHits: number, resetTime: Date }>}
   */
  async increment(key) {
    try {
      const result = await this._evalLua(key, this.windowMs);
      const totalHits = Number(result[0]);
      const ttlMs = Number(result[1]);
      const resetTime = new Date(Date.now() + Math.max(0, ttlMs));

      return {
        totalHits,
        resetTime
      };
    } catch (err) {
      this.logger.error('REDIS_STORE_ERROR', `Redis rate-limiter store failure: ${err.message}`, {
        details: { key, error: err.message }
      });

      if (!this.passOnConnectionError) {
        throw err;
      }

      // Fail open: return non-blocking hit count
      return {
        totalHits: 1,
        resetTime: new Date(Date.now() + this.windowMs)
      };
    }
  }

  /**
   * Decrement hits for a key.
   *
   * @param {string} key
   * @returns {Promise<void>}
   */
  async decrement(key) {
    try {
      const fullKey = this._prefixKey(key);
      if (typeof this.client.decr === 'function') {
        await this.client.decr(fullKey);
      }
    } catch (err) {
      this.logger.warn('REDIS_STORE_ERROR', `Redis decrement failed: ${err.message}`, {
        details: { key }
      });
    }
  }

  /**
   * Reset hits for a single key.
   *
   * @param {string} key
   * @returns {Promise<void>}
   */
  async resetKey(key) {
    try {
      const fullKey = this._prefixKey(key);
      if (typeof this.client.del === 'function') {
        await this.client.del(fullKey);
      }
    } catch (err) {
      this.logger.warn('REDIS_STORE_ERROR', `Redis resetKey failed: ${err.message}`, {
        details: { key }
      });
    }
  }

  /**
   * Reset all keys matching prefix.
   *
   * @returns {Promise<void>}
   */
  async resetAll() {
    try {
      const pattern = `${this.prefix}*`;
      let keys = [];

      if (typeof this.client.keys === 'function') {
        keys = await this.client.keys(pattern);
      }

      if (keys && keys.length > 0 && typeof this.client.del === 'function') {
        await this.client.del(...keys);
      }
    } catch (err) {
      this.logger.warn('REDIS_STORE_ERROR', `Redis resetAll failed: ${err.message}`);
    }
  }

  /**
   * Retrieve current hits for a key without incrementing.
   *
   * @param {string} key
   * @returns {Promise<{ totalHits: number, resetTime: Date } | undefined>}
   */
  async get(key) {
    try {
      const fullKey = this._prefixKey(key);
      const [hits, ttl] = await Promise.all([
        this.client.get ? this.client.get(fullKey) : null,
        this.client.pttl ? this.client.pttl(fullKey) : null
      ]);

      if (!hits) {
        return undefined;
      }

      const totalHits = parseInt(hits, 10);
      const ttlMs = parseInt(ttl, 10) || this.windowMs;

      return {
        totalHits,
        resetTime: new Date(Date.now() + Math.max(0, ttlMs))
      };
    } catch (err) {
      this.logger.warn('REDIS_STORE_ERROR', `Redis get failed: ${err.message}`);
      return undefined;
    }
  }
}

module.exports = {
  RedisStore
};

