'use strict';

const ipaddr = require('ipaddr.js');

/**
 * Normalizes an IP string into a standard ipaddr.IPv4 or ipaddr.IPv6 object.
 * Converts IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1) to pure IPv4.
 *
 * @param {string} ipString
 * @returns {ipaddr.IPv4|ipaddr.IPv6|null}
 */
function parseIp(ipString) {
  if (typeof ipString !== 'string') {
    return null;
  }

  const clean = ipString.trim();
  if (!clean) {
    return null;
  }

  try {
    let parsed = ipaddr.parse(clean);
    // Convert IPv4-mapped IPv6 to pure IPv4
    if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
      parsed = parsed.toIPv4Address();
    }
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Parses an IP rule which can be a single IP or CIDR range.
 *
 * @param {string} ruleString
 * @returns {{ type: 'cidr'|'ip', parsed: ipaddr.IPv4|ipaddr.IPv6|Array<any> } | null}
 */
function parseRule(ruleString) {
  if (typeof ruleString !== 'string') {
    return null;
  }

  const trimmed = ruleString.trim();
  if (!trimmed) {
    return null;
  }

  // Check if CIDR notation
  if (trimmed.includes('/')) {
    try {
      const cidr = ipaddr.parseCIDR(trimmed);
      return { type: 'cidr', parsed: cidr, raw: trimmed };
    } catch {
      return null;
    }
  }

  // Single IP
  const parsedIp = parseIp(trimmed);
  if (parsedIp) {
    return { type: 'ip', parsed: parsedIp, raw: trimmed };
  }

  return null;
}

/**
 * Checks if a given IP address matches a compiled rule.
 *
 * @param {ipaddr.IPv4|ipaddr.IPv6} clientIp
 * @param {Object} rule
 * @returns {boolean}
 */
function matchesRule(clientIp, rule) {
  if (!clientIp || !rule) {
    return false;
  }

  if (rule.type === 'ip') {
    return clientIp.toString() === rule.parsed.toString();
  }

  if (rule.type === 'cidr') {
    try {
      return clientIp.match(rule.parsed);
    } catch {
      // Kind mismatch (e.g. matching IPv6 client against IPv4 CIDR)
      return false;
    }
  }

  return false;
}

/**
 * Checks if a client IP matches any rule in an array of rules.
 *
 * @param {string} clientIpStr
 * @param {Array<Object>} compiledRules
 * @returns {boolean}
 */
function isIpInRules(clientIpStr, compiledRules) {
  const parsedClient = parseIp(clientIpStr);
  if (!parsedClient) {
    return false;
  }

  for (const rule of compiledRules) {
    if (matchesRule(parsedClient, rule)) {
      return true;
    }
  }

  return false;
}

/**
 * Compiles a list of IP and CIDR rule strings into parsed rule objects.
 *
 * @param {string[]} ruleStrings
 * @returns {Array<Object>}
 */
function compileRules(ruleStrings = []) {
  if (!Array.isArray(ruleStrings)) {
    return [];
  }

  return ruleStrings
    .map((r) => parseRule(r))
    .filter((r) => r !== null);
}

/**
 * Safely extracts client IP according to proxy configuration.
 * Never blindly trusts X-Forwarded-For unless explicitly configured.
 *
 * @param {import('express').Request} req
 * @param {Object} [options]
 * @param {boolean|string[]|number|Function} [options.trustProxy=false]
 * @returns {string} Extracted client IP
 */
function getClientIp(req, options = {}) {
  const trustProxy = options.trustProxy !== undefined ? options.trustProxy : false;

  // Custom function
  if (typeof options.getIp === 'function') {
    return options.getIp(req);
  }

  const directIp = (req.socket && req.socket.remoteAddress) ||
    (req.connection && req.connection.remoteAddress) ||
    '127.0.0.1';

  if (!trustProxy) {
    // When trustProxy is disabled, ONLY use direct socket address
    const parsed = parseIp(directIp);
    return parsed ? parsed.toString() : directIp;
  }

  // If trustProxy is boolean true, rely on express req.ip if available
  if (trustProxy === true) {
    if (req.ip) {
      const parsed = parseIp(req.ip);
      return parsed ? parsed.toString() : req.ip;
    }
  }

  // If X-Forwarded-For is present and proxy is trusted
  const xForwardedFor = req.headers && req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    const rawList = Array.isArray(xForwardedFor) ? xForwardedFor.join(',') : xForwardedFor;
    const ips = rawList.split(',').map((s) => s.trim()).filter(Boolean);

    if (ips.length > 0) {
      if (typeof trustProxy === 'number') {
        // Trust specified number of hops from the right
        const index = Math.max(0, ips.length - trustProxy);
        const targetIp = ips[index] || directIp;
        const parsed = parseIp(targetIp);
        return parsed ? parsed.toString() : targetIp;
      }

      if (Array.isArray(trustProxy)) {
        // Trust only if directIp is in the trusted proxy list
        const trustedRules = compileRules(trustProxy);
        if (isIpInRules(directIp, trustedRules)) {
          // Find first untrusted IP walking backwards from right to left
          for (let i = ips.length - 1; i >= 0; i--) {
            if (!isIpInRules(ips[i], trustedRules)) {
              const parsed = parseIp(ips[i]);
              return parsed ? parsed.toString() : ips[i];
            }
          }
          // All are trusted; return the leftmost
          const parsed = parseIp(ips[0]);
          return parsed ? parsed.toString() : ips[0];
        } else {
          // Direct connection is not a trusted proxy! Reject X-Forwarded-For header spoofing
          const parsed = parseIp(directIp);
          return parsed ? parsed.toString() : directIp;
        }
      }

      // Boolean true fallback: take the first valid IP
      const parsed = parseIp(ips[0]);
      return parsed ? parsed.toString() : ips[0];
    }
  }

  const parsed = parseIp(directIp);
  return parsed ? parsed.toString() : directIp;
}

module.exports = {
  parseIp,
  parseRule,
  matchesRule,
  isIpInRules,
  compileRules,
  getClientIp
};

