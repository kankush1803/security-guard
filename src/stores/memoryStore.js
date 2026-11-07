'use strict';

/**
 * In-memory store for rate limiting with automatic background cleanup.
 */
class MemoryStore {
  /**
   * @param {Object} [options]
   * @param {number} [options.windowMs=60000] - Window duration in milliseconds.
   * @param {number} [options.cleanupIntervalMs=60000] - How often expired keys are purged.
   */
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60000;
    this.hits = new Map();

    const cleanupMs = options.cleanupIntervalMs || Math.min(this.windowMs, 60000);
    this.interval = setInterval(() => this.cleanup(), cleanupMs);
    // Unref so the cleanup interval does not block Node process exit
    if (this.interval.unref) {
      this.interval.unref();
    }
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
   * Purge expired rate limit entries.
   */
  cleanup() {
    const now = Date.now();
    for (const [key, record] of this.hits.entries()) {
      if (record.resetTime <= now) {
        this.hits.delete(key);
      }
    }
  }

  /**
   * Increment hits for a key.
   *
   * @param {string} key
   * @returns {Promise<{ totalHits: number, resetTime: Date }>}
   */
  async increment(key) {
    const now = Date.now();
    let record = this.hits.get(key);

    if (!record || record.resetTime <= now) {
      record = {
        totalHits: 1,
        resetTime: now + this.windowMs
      };
      this.hits.set(key, record);
    } else {
      record.totalHits += 1;
    }

    return {
      totalHits: record.totalHits,
      resetTime: new Date(record.resetTime)
    };
  }

  /**
   * Decrement hits for a key.
   *
   * @param {string} key
   * @returns {Promise<void>}
   */
  async decrement(key) {
    const record = this.hits.get(key);
    if (record && record.totalHits > 0) {
      record.totalHits -= 1;
    }
  }

  /**
   * Reset hits for a single key.
   *
   * @param {string} key
   * @returns {Promise<void>}
   */
  async resetKey(key) {
    this.hits.delete(key);
  }

  /**
   * Reset all keys in memory.
   *
   * @returns {Promise<void>}
   */
  async resetAll() {
    this.hits.clear();
  }

  /**
   * Retrieve current hits for a key without incrementing.
   *
   * @param {string} key
   * @returns {Promise<{ totalHits: number, resetTime: Date } | undefined>}
   */
  async get(key) {
    const record = this.hits.get(key);
    if (!record || record.resetTime <= Date.now()) {
      return undefined;
    }
    return {
      totalHits: record.totalHits,
      resetTime: new Date(record.resetTime)
    };
  }

  /**
   * Clean up timer on teardown.
   */
  shutdown() {
    if (this.interval) {
      clearInterval(this.interval);
    }
    this.hits.clear();
  }
}

module.exports = {
  MemoryStore
};

