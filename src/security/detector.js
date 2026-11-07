'use strict';

/**
 * High-confidence threat detection signatures.
 *
 * NOTE: Pattern matching is an auxiliary defense-in-depth heuristic, NOT a replacement
 * for parameterized SQL queries, context-aware output encoding, or rigorous input validation.
 */
const DEFAULT_THREAT_PATTERNS = [
  {
    id: 'PATH_TRAVERSAL',
    name: 'Directory / Path Traversal Attack',
    pattern: /(?:\.\.[/\\]|[/\\]\.\.|\.\.%2f|%2e%2e%2f|%2e%2e\/|\.\.%5c|%2e%2e%5c)/i,
    severity: 'high'
  },
  {
    id: 'NULL_BYTE_INJECTION',
    name: 'Null Byte Injection',
    pattern: /(?:\x00|%00|\\0)/i,
    severity: 'high'
  },
  {
    id: 'COMMAND_INJECTION',
    name: 'Suspicious Shell Command Injection',
    pattern: /(?:;\s*(?:cat|chmod|curl|wget|rm|bash|sh|whoami|nc|netcat|powershell)\b|\|\s*(?:bash|sh|curl|wget|powershell)\b|`\s*(?:cat|curl|wget|rm|bash|sh|whoami)\s*`|\$\(\s*(?:cat|curl|wget|rm|bash|sh|whoami)\s*\))/i,
    severity: 'high'
  },
  {
    id: 'SCRIPT_TAG_INJECTION',
    name: 'Suspicious Inline Script / JavaScript Scheme',
    pattern: /(?:<\s*script\b[^>]*>|javascript\s*:\s*(?:alert|document|window|location|eval|prompt)\b|data\s*:\s*text\/html)/i,
    severity: 'medium'
  },
  {
    id: 'PROTOTYPE_POLLUTION',
    name: 'Prototype Pollution Attempt',
    pattern: /(?:__proto__|constructor\s*\[\s*['"]?prototype['"]?\s*\]|prototype\s*\.\s*constructor)/i,
    severity: 'high'
  },
  {
    id: 'SSTI_INJECTION',
    name: 'Suspicious Template Injection (SSTI)',
    pattern: /(?:\{\{\s*(?:constructor|process|require|mainModule|__proto__)\s*\}\}|<%\s*=\s*(?:process|require)\s*%>)/i,
    severity: 'high'
  }
];

/**
 * Evaluates a threat rule against a string value.
 *
 * @param {Object} rule
 * @param {string} value
 * @param {string} path
 * @param {string} [snippetPrefix]
 * @returns {Object|null}
 */
function matchRule(rule, value, path, snippetPrefix) {
  let matched = false;
  if (typeof rule.pattern === 'function') {
    matched = Boolean(rule.pattern(value, path));
  } else if (rule.pattern instanceof RegExp) {
    matched = rule.pattern.test(value);
  }

  if (matched) {
    const raw = snippetPrefix ? `${snippetPrefix}: ${value}` : value;
    return {
      ruleId: rule.id || 'CUSTOM_RULE',
      ruleName: rule.name || 'Custom Threat Rule',
      path,
      snippet: raw.length > 80 ? `${raw.substring(0, 80)}...` : raw,
      severity: rule.severity || 'medium'
    };
  }
  return null;
}

/**
 * Recursively inspects values in strings, arrays, or objects for threat signatures.
 *
 * @param {any} value - Value to inspect.
 * @param {Array<Object>} rules - Compiled threat rules.
 * @param {string} [currentPath=''] - Current object path for error reporting.
 * @param {string[]} [whitelistedKeys=[]] - Keys to skip inspection.
 * @param {Set<any>} [seen] - Visited objects to prevent infinite loops.
 * @returns {Array<{ ruleId: string, ruleName: string, path: string, snippet: string, severity: string }>}
 */
function scanValue(value, rules, currentPath = '', whitelistedKeys = [], seen = new Set()) {
  const matches = [];

  if (value === null || value === undefined || seen.has(value)) {
    return matches;
  }

  // Handle strings
  if (typeof value === 'string') {
    for (const rule of rules) {
      const match = matchRule(rule, value, currentPath);
      if (match) matches.push(match);
    }
    return matches;
  }

  // Handle Arrays
  if (Array.isArray(value)) {
    seen.add(value);
    for (let i = 0; i < value.length; i++) {
      const arrayPath = currentPath ? `${currentPath}[${i}]` : `[${i}]`;
      matches.push(...scanValue(value[i], rules, arrayPath, whitelistedKeys, seen));
    }
    return matches;
  }

  // Handle Objects
  if (typeof value === 'object') {
    seen.add(value);

    // Get all own property names including non-enumerable or __proto__
    const propNames = Object.getOwnPropertyNames(value);
    for (const propName of propNames) {
      const keyPath = currentPath ? `${currentPath}.${propName}` : propName;
      for (const rule of rules) {
        const match = matchRule(rule, propName, keyPath, 'Key name');
        if (match) matches.push(match);
      }
    }

    // Check if prototype was directly manipulated
    try {
      const proto = Object.getPrototypeOf(value);
      if (proto && proto !== Object.prototype && proto.constructor !== Object && typeof proto === 'object') {
        matches.push({
          ruleId: 'PROTOTYPE_POLLUTION',
          ruleName: 'Prototype Pollution Attempt',
          path: currentPath ? `${currentPath}.__proto__` : '__proto__',
          snippet: 'Object has non-standard prototype',
          severity: 'high'
        });
      }
    } catch {
      // Ignore prototype check failures on odd object types
    }

    for (const [key, val] of Object.entries(value)) {
      if (whitelistedKeys.includes(key.toLowerCase())) {
        continue;
      }
      const childPath = currentPath ? `${currentPath}.${key}` : key;
      matches.push(...scanValue(val, rules, childPath, whitelistedKeys, seen));
    }
  }

  return matches;
}

module.exports = {
  DEFAULT_THREAT_PATTERNS,
  scanValue
};
