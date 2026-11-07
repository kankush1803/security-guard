'use strict';

const crypto = require('crypto');

/**
 * Hash an API key using the specified algorithm (default: sha256).
 *
 * @param {string} rawKey - Plaintext API key.
 * @param {string} [algorithm='sha256'] - Hashing algorithm.
 * @returns {string} Hex-encoded hash.
 */
function hashApiKey(rawKey, algorithm = 'sha256') {
  if (typeof rawKey !== 'string' || !rawKey) {
    throw new Error('API key must be a non-empty string.');
  }
  return crypto.createHash(algorithm).update(rawKey, 'utf8').digest('hex');
}

/**
 * Generate a cryptographically secure random API key.
 *
 * @param {Object} [options]
 * @param {string} [options.prefix='sag_'] - Key prefix (e.g. 'sag_live_', 'sag_test_').
 * @param {number} [options.bytes=32] - Number of random bytes.
 * @param {string} [options.algorithm='sha256'] - Hash algorithm for returned hash.
 * @returns {{ key: string, hash: string, prefix: string }}
 */
function generateApiKey(options = {}) {
  const prefix = options.prefix || 'sag_';
  const byteLength = options.bytes && options.bytes >= 16 ? options.bytes : 32;
  const algorithm = options.algorithm || 'sha256';

  const randomPart = crypto.randomBytes(byteLength).toString('base64url');
  const key = `${prefix}${randomPart}`;
  const hash = hashApiKey(key, algorithm);

  return {
    key,
    hash,
    prefix
  };
}

/**
 * Constant-time comparison between two hashes to prevent timing attacks.
 *
 * @param {string} a - First hash hex string.
 * @param {string} b - Second hash hex string.
 * @returns {boolean} True if hashes match.
 */
function secureCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    // Constant time dummy comparison to avoid leaking length differences
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Check if a key record is expired.
 *
 * @param {Object} keyRecord
 * @param {Date|string|number} [keyRecord.expiresAt]
 * @returns {boolean}
 */
function isKeyExpired(keyRecord) {
  if (!keyRecord || !keyRecord.expiresAt) {
    return false;
  }

  const expiresTime = new Date(keyRecord.expiresAt).getTime();
  return !Number.isNaN(expiresTime) && Date.now() > expiresTime;
}

module.exports = {
  hashApiKey,
  generateApiKey,
  secureCompare,
  isKeyExpired
};

