'use strict';

/**
 * infoDisclosure.js — client-side secrets, verbose errors, directory listing
 * (Configuration Management / Information Gathering).
 */

const { URL } = require('url');

const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

const SECRET_PATTERNS = [
  { name: 'AWS Access Key', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'Google API Key', re: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: 'Slack Token', re: /xox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: 'Private Key block', re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
  { name: 'Generic API key assignment', re: /(?:api[_-]?key|secret|passwd|password)["'\s:=]{1,4}[A-Za-z0-9\-_]{16,}/i },
  { name: 'Bearer/JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
];

function extractScripts(html, baseUrl) {
  const urls = [];
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      urls.push(new URL(m[1], baseUrl).toString());
    } catch {
      /* ignore */
    }
  }
  return urls;
}

function scan(text, source, sourceUrl, log, finding) {
  for (const p of SECRET_PATTERNS) {
    const m = p.re.exec(text);
    if (m) {
      const snippet = m[0].slice(0, 12) + '…';
      log('vuln', `Possible ${p.name} in ${source}`);
      finding({
        category: 'Configuration Management',
        title: `Possible secret in client-side code (${p.name})`,
        status: 'fail', severity: 'high',
        evidence: `${source}: ${snippet}`,
        remediation:
          'Remove secrets from client-delivered code; rotate any exposed credential.',
        reference: REF,
        request: { method: 'GET', url: sourceUrl },
      });
    }
  }
}

async function run(ctx) {
  const { http, target, log, finding } = ctx;
  let res = ctx.shared.baseResponse;
  if (!res) {
    try {
      res = await http.request(target, { timeout: 12000 });
    } catch (e) {
      log('warn', `Info disclosure fetch failed: ${e.message}`);
      return;
    }
  }

  log('info', 'Scanning HTML and linked scripts for exposed secrets...');
  scan(res.body || '', 'HTML body', res.finalUrl, log, finding);

  const scripts = extractScripts(res.body || '', res.finalUrl).slice(0, 8);
  log('debug', `Inspecting ${scripts.length} linked script(s)`);
  for (const s of scripts) {
    try {
      const r = await http.request(s, { timeout: 10000 });
      scan(r.body || '', s.split('/').pop(), s, log, finding);
    } catch (e) {
      log('debug', `script fetch ${s}: ${e.message}`);
    }
  }

  // Directory listing / verbose errors on a random path
  const origin = new URL(target);
  const probe = `${origin.protocol}//${origin.host}/smartscan-${Date.now()}/`;
  try {
    const r = await http.request(probe, { timeout: 9000 });
    if (/Index of \/|Directory listing for/i.test(r.body || '')) {
      log('vuln', 'Directory listing enabled');
      finding({
        category: 'Configuration Management', title: 'Directory listing enabled',
        status: 'fail', severity: 'medium',
        evidence: 'Autoindex/directory-listing markup detected.',
        remediation: 'Disable automatic directory listing (autoindex).', reference: REF,
        request: { method: 'GET', url: probe, status: r.status },
      });
    }
    if (/stack trace|Exception|at [\w.$]+\(.+:\d+\)|Traceback \(most recent/i.test(r.body || '')) {
      log('warn', 'Verbose error / stack trace disclosure detected');
      finding({
        category: 'Configuration Management', title: 'Verbose error disclosure',
        status: 'warn', severity: 'low',
        evidence: (r.body || '').slice(0, 160),
        remediation: 'Return generic error pages; log details server-side only.',
        reference: REF,
        request: { method: 'GET', url: probe, status: r.status },
      });
    } else {
      log('ok', 'No obvious verbose error disclosure on 404 path');
    }
  } catch (e) {
    log('debug', `error-page probe: ${e.message}`);
  }
}

module.exports = { id: 'infoDisclosure', category: 'Configuration Management', run };
