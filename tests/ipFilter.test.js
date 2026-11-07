'use strict';

const express = require('express');
const request = require('supertest');
const { ipFilter, parseIp, parseRule, matchesRule, isIpInRules } = require('../src');

describe('IP Filtering & IP Security', () => {
  describe('IP Utility & CIDR Parsing', () => {
    it('should parse valid IPv4 and IPv6 addresses', () => {
      const ipv4 = parseIp('192.168.1.50');
      expect(ipv4).not.toBeNull();
      expect(ipv4.kind()).toBe('ipv4');

      const ipv6 = parseIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      expect(ipv6).not.toBeNull();
      expect(ipv6.kind()).toBe('ipv6');
    });

    it('should normalize IPv4-mapped IPv6 to IPv4', () => {
      const mapped = parseIp('::ffff:192.168.1.100');
      expect(mapped).not.toBeNull();
      expect(mapped.kind()).toBe('ipv4');
      expect(mapped.toString()).toBe('192.168.1.100');
    });

    it('should return null for malformed IP strings', () => {
      expect(parseIp('not-an-ip')).toBeNull();
      expect(parseIp('')).toBeNull();
      expect(parseIp(null)).toBeNull();
    });

    it('should match IPv4 CIDR ranges correctly', () => {
      const rule = parseRule('192.168.1.0/24');
      expect(rule.type).toBe('cidr');

      const clientIn = parseIp('192.168.1.45');
      const clientOut = parseIp('192.168.2.1');

      expect(matchesRule(clientIn, rule)).toBe(true);
      expect(matchesRule(clientOut, rule)).toBe(false);
    });

    it('should match IPv6 CIDR ranges correctly', () => {
      const rule = parseRule('2001:db8::/32');
      expect(rule.type).toBe('cidr');

      const clientIn = parseIp('2001:db8:ffff::1');
      const clientOut = parseIp('2001:db9::1');

      expect(matchesRule(clientIn, rule)).toBe(true);
      expect(matchesRule(clientOut, rule)).toBe(false);
    });
  });

  describe('IP Filter Middleware', () => {
    function createApp(filterOptions) {
      const app = express();
      app.use(ipFilter(filterOptions));
      app.get('/test', (req, res) => {
        res.json({ success: true, clientIp: req.clientIp });
      });
      return app;
    }

    it('should block requests in blocklist mode when IP matches', async () => {
      const app = createApp({
        mode: 'blocklist',
        blocklist: ['192.168.1.100', '10.0.0.0/8'],
        getIp: (req) => req.headers['x-mock-ip'] || '127.0.0.1'
      });

      // Allowed IP
      const resAllowed = await request(app).get('/test').set('x-mock-ip', '192.168.1.99');
      expect(resAllowed.status).toBe(200);
      expect(resAllowed.body.clientIp).toBe('192.168.1.99');

      // Blocked single IP
      const resBlockedIp = await request(app).get('/test').set('x-mock-ip', '192.168.1.100');
      expect(resBlockedIp.status).toBe(403);
      expect(resBlockedIp.body.error.code).toBe('FORBIDDEN');

      // Blocked CIDR
      const resBlockedCidr = await request(app).get('/test').set('x-mock-ip', '10.5.20.1');
      expect(resBlockedCidr.status).toBe(403);
    });

    it('should allow only allowlisted IPs in allowlist mode and block all others', async () => {
      const app = createApp({
        mode: 'allowlist',
        allowlist: ['203.0.113.50', '172.16.0.0/12'],
        getIp: (req) => req.headers['x-mock-ip'] || '127.0.0.1'
      });

      // In allowlist single IP
      const resAllowed1 = await request(app).get('/test').set('x-mock-ip', '203.0.113.50');
      expect(resAllowed1.status).toBe(200);

      // In allowlist CIDR
      const resAllowed2 = await request(app).get('/test').set('x-mock-ip', '172.20.1.1');
      expect(resAllowed2.status).toBe(200);

      // Not in allowlist
      const resDenied = await request(app).get('/test').set('x-mock-ip', '8.8.8.8');
      expect(resDenied.status).toBe(403);
      expect(resDenied.body.error.code).toBe('FORBIDDEN');
    });

    it('should NEVER blindly trust X-Forwarded-For when trustProxy is false (anti-spoofing)', async () => {
      const app = express();
      // trustProxy is false by default
      app.use(
        ipFilter({
          mode: 'blocklist',
          blocklist: ['127.0.0.1'], // local socket address is 127.0.0.1 in supertest
          trustProxy: false
        })
      );
      app.get('/test', (req, res) => res.json({ success: true }));

      // Attacker tries to spoof an innocent public IP in X-Forwarded-For
      const res = await request(app)
        .get('/test')
        .set('X-Forwarded-For', '93.184.216.34'); // example.com IP

      // Because trustProxy is false, socket address 127.0.0.1 was used and blocked!
      expect(res.status).toBe(403);
    });

    it('should safely extract client IP when trusted proxies are explicitly configured', async () => {
      const app = express();
      app.use(
        ipFilter({
          mode: 'allowlist',
          allowlist: ['203.0.113.195'],
          // Supertest connects from 127.0.0.1, so we configure 127.0.0.1 as a trusted proxy
          trustProxy: ['127.0.0.1']
        })
      );
      app.get('/test', (req, res) => res.json({ success: true, ip: req.clientIp }));

      // Client IP forwarded through our trusted proxy
      const res = await request(app)
        .get('/test')
        .set('X-Forwarded-For', '203.0.113.195, 127.0.0.1');

      expect(res.status).toBe(200);
      expect(res.body.ip).toBe('203.0.113.195');
    });
  });
});

