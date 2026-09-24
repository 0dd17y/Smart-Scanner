'use strict';

/**
 * configManagement.js — exposed/backup files, admin URLs, HTTP methods & TRACE/XST.
 */

const { URL } = require('url');

const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

// `match` = a signature the body must contain for the file to count as GENUINELY
// exposed. Many WAFs/CDNs answer blocked files with HTTP 200 + an "Access Denied"
// page, so status 200 alone is not evidence of exposure.
const SENSITIVE_FILES = [
  { path: '/.git/HEAD', sev: 'high', why: 'Exposed .git repository', match: /^\s*(ref:\s*refs\/|[0-9a-f]{40})/m },
  { path: '/.env', sev: 'high', why: 'Exposed environment file (may contain secrets)', match: /^[A-Z][A-Z0-9_]*\s*=/m },
  { path: '/.DS_Store', sev: 'low', why: 'macOS directory metadata leak', match: /Bud1/ },
  { path: '/config.php.bak', sev: 'high', why: 'Backup source file', match: /<\?php|<\?=/ },
  { path: '/web.config', sev: 'medium', why: 'IIS configuration exposure', match: /<configuration|<system\.web/i },
  { path: '/.well-known/security.txt', sev: 'info', why: 'security.txt present (good practice)', good: true, match: /Contact\s*:|Policy\s*:|Expires\s*:/i },
  { path: '/phpinfo.php', sev: 'medium', why: 'phpinfo output exposes environment', match: /phpinfo\(\)|PHP Version|<title>phpinfo/i },
  { path: '/backup.zip', sev: 'high', why: 'Downloadable backup archive', match: /^PK\x03\x04/ },
];

const ADMIN_PATHS = ['/admin', '/administrator', '/login', '/wp-admin/', '/phpmyadmin/', '/manager/html'];

// Signatures of WAF/CDN/server "blocked" responses that are commonly served with a
// 200 status. When a body matches this, the resource is NOT actually accessible.
const DENIAL_RE = /access denied|you don'?t have permission|not authorized|request rejected|forbidden|edgesuite\.net|akamai|attention required|cloudflare|blocked|captcha|incident id|support id|mod_security|406 not acceptable/i;

// Normalized-length similarity: true if two bodies look like the same template.
function sameTemplate(a, b) {
  if (!a || !b) return false;
  const la = a.length, lb = b.length;
  if (la === 0 || lb === 0) return false;
  return Math.abs(la - lb) <= Math.max(24, la * 0.05);
}

async function run(ctx) {
  const { http, target, log, finding } = ctx;
  const origin = new URL(target);
  const base = `${origin.protocol}//${origin.host}`;

  // --- Sensitive / backup files ---
  log('info', 'Probing for exposed sensitive and backup files...');

  // Baseline: request a file that cannot exist. Its response is the server/WAF's
  // "nothing here / blocked" template, which we use to reject look-alike 200s.
  let baselineBody = '';
  try {
    const bl = await http.request(`${base}/smartscan-none-${Date.now()}.bak`, { timeout: 9000 });
    baselineBody = bl.body || '';
    log('debug', `Not-found baseline: HTTP ${bl.status}, ${baselineBody.length} bytes` +
      (DENIAL_RE.test(baselineBody) ? ' (looks like a block page)' : ''));
  } catch (e) {
    log('debug', `baseline probe failed: ${e.message}`);
  }

  for (const f of SENSITIVE_FILES) {
    const url = base + f.path;
    try {
      const r = await http.request(url, { timeout: 9000 });
      const body = r.body || '';

      // Only a 200 with a body is a candidate at all.
      if (r.status !== 200 || body.length === 0) {
        log('debug', `${f.path}: HTTP ${r.status} — not accessible`);
        continue;
      }
      // WAF/CDN "Access Denied" page served with a 200 status.
      if (DENIAL_RE.test(body)) {
        log('ok', `${f.path}: blocked (200 with an access-denied page) — not exposed`);
        continue;
      }
      // Same template as the not-found baseline (soft-404 / generic page).
      if (sameTemplate(body, baselineBody) && !(f.match && f.match.test(body))) {
        log('ok', `${f.path}: 200 but matches the not-found template — not exposed`);
        continue;
      }
      // Body must actually look like the target file's contents.
      if (f.match && !f.match.test(body)) {
        log('debug', `${f.path}: HTTP 200 but content does not match ${f.path} signature — skipping`);
        continue;
      }

      if (f.good) {
        log('ok', `security.txt present`);
        finding({
          category: 'Configuration Management', title: 'security.txt present',
          status: 'pass', severity: 'info', evidence: body.slice(0, 200),
          remediation: 'No action required.', reference: REF,
          request: { method: 'GET', url },
        });
      } else {
        log('vuln', `${f.path} is accessible and content matches — ${f.why}`);
        finding({
          category: 'Configuration Management', title: `Exposed file: ${f.path}`,
          status: 'fail', severity: f.sev,
          evidence: `HTTP 200 at ${url} with matching content:\n${body.slice(0, 160)}`,
          remediation: `Remove or block access to ${f.path}. ${f.why}.`,
          reference: REF,
          request: { method: 'GET', url, status: r.status },
        });
      }
    } catch (e) {
      log('debug', `${f.path}: ${e.message}`);
    }
  }

  // --- Admin URLs ---
  log('info', 'Checking for common administrative endpoints...');
  for (const p of ADMIN_PATHS) {
    const url = base + p;
    try {
      const r = await http.request(url, { timeout: 9000 });
      const blocked = r.status === 200 && DENIAL_RE.test(r.body || '');
      if ((r.status === 200 || r.status === 401 || r.status === 403) && !blocked) {
        // A 200 reachable panel is more notable than a 401/403 (exists but protected).
        log('warn', `Admin endpoint ${p} responded HTTP ${r.status}`);
        finding({
          category: 'Configuration Management', title: `Administrative endpoint: ${p}`,
          status: 'warn', severity: r.status === 200 ? 'medium' : 'low',
          evidence: `HTTP ${r.status} at ${url}` + (r.status !== 200 ? ' (present but protected)' : ''),
          remediation: 'Restrict admin interfaces by network/IP and strong auth.',
          reference: REF,
          request: { method: 'GET', url, status: r.status },
        });
      } else if (blocked) {
        log('ok', `Admin endpoint ${p}: blocked by WAF/CDN (200 denial page)`);
      } else {
        log('debug', `${p}: HTTP ${r.status}`);
      }
    } catch (e) {
      log('debug', `${p}: ${e.message}`);
    }
  }

  // --- HTTP methods + TRACE/XST ---
  log('info', 'Enumerating allowed HTTP methods (OPTIONS) and testing TRACE...');
  try {
    const opt = await http.request(base + '/', { method: 'OPTIONS', timeout: 9000 });
    const allow = opt.headers['allow'] || opt.headers['access-control-allow-methods'];
    if (allow) {
      log('info', `Allowed methods: ${allow}`);
      const risky = /PUT|DELETE|TRACE|CONNECT|PATCH/i.test(allow);
      finding({
        category: 'Configuration Management', title: 'HTTP methods allowed',
        status: risky ? 'warn' : 'info', severity: risky ? 'low' : 'info',
        evidence: `Allow: ${allow}`,
        remediation: risky
          ? 'Disable unused/risky methods (PUT, DELETE, TRACE, CONNECT) unless required.'
          : 'No action required.',
        reference: REF,
      });
    } else {
      log('debug', 'No Allow header returned by OPTIONS.');
    }
  } catch (e) {
    log('debug', `OPTIONS failed: ${e.message}`);
  }

  try {
    const tr = await http.request(base + '/', { method: 'TRACE', timeout: 9000 });
    if (tr.status === 200 && /TRACE/i.test(tr.body || '')) {
      log('vuln', 'TRACE method enabled (Cross-Site Tracing / XST risk)');
      finding({
        category: 'Configuration Management', title: 'TRACE method enabled (XST)',
        status: 'fail', severity: 'medium',
        evidence: `TRACE returned ${tr.status} and echoed the request.`,
        remediation: 'Disable the HTTP TRACE method on the server.', reference: REF,
        request: { method: 'TRACE', url: base + '/', status: tr.status },
      });
    } else {
      log('ok', 'TRACE method not enabled');
    }
  } catch (e) {
    log('debug', `TRACE failed: ${e.message}`);
  }
}

module.exports = { id: 'configManagement', category: 'Configuration Management', run };
