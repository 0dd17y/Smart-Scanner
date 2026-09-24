'use strict';

/**
 * fuzzer.js — AGGRESSIVE ONLY. ffuf-style directory / content discovery using a
 * bundled, configurable wordlist. Bounded by options.maxFuzz. Establishes a
 * soft-404 baseline so wildcard responses do not cause false positives.
 */

const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

function loadWords(maxFuzz) {
  const file = path.join(__dirname, '..', 'wordlists', 'dirs.txt');
  let lines = [];
  try {
    lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter((l) => l && !l.startsWith('#'));
  } catch {
    lines = ['admin', 'backup', 'test', 'api', 'config', 'uploads', 'old', 'dev'];
  }
  return lines.slice(0, maxFuzz);
}

async function run(ctx) {
  const { http, target, log, finding, options } = ctx;
  if (options.intensity !== 'aggressive') {
    log('debug', 'Content fuzzing skipped (requires Aggressive intensity).');
    return;
  }

  const origin = new URL(target);
  const base = `${origin.protocol}//${origin.host}`;
  const maxFuzz = Math.min(options.maxFuzz || 120, 1000);
  const words = loadWords(maxFuzz);
  log('info', `Content discovery: fuzzing ${words.length} path(s) under ${base} ...`);

  // Soft-404 baseline
  let baseLen = -1;
  let baseStatus = 404;
  try {
    const r = await http.request(`${base}/smartscan-nope-${Date.now()}`, { timeout: 9000 });
    baseLen = (r.body || '').length;
    baseStatus = r.status;
    log('debug', `Soft-404 baseline: HTTP ${baseStatus}, ${baseLen} bytes`);
  } catch (e) {
    log('debug', `baseline probe failed: ${e.message}`);
  }

  let hits = 0;
  for (const w of words) {
    const url = `${base}/${w}`;
    let r;
    try {
      r = await http.request(url, { timeout: 8000, followRedirects: false });
    } catch (e) {
      log('debug', `${w}: ${e.message}`);
      continue;
    }
    // Bare 301/302 are excluded: on login-gated apps most paths redirect to a login/SSO
    // page (that is protection, not a finding) and would flood the feed with noise.
    const interesting =
      (r.status === 200 && Math.abs((r.body || '').length - baseLen) > 30) ||
      r.status === 401 || r.status === 403;

    if (interesting && r.status !== baseStatus) {
      hits++;
      const sev = r.status === 200 ? 'low' : 'info';
      log('warn', `Discovered: /${w} -> HTTP ${r.status}`);
      finding({
        category: 'Configuration Management', title: `Discovered path: /${w}`,
        status: r.status === 401 || r.status === 403 ? 'info' : 'warn',
        severity: sev,
        evidence: `HTTP ${r.status} at ${url}`,
        remediation:
          'Confirm this path should be exposed; remove or protect unreferenced content.',
        reference: REF,
        request: { method: 'GET', url, status: r.status },
      });
    } else {
      log('debug', `/${w} -> HTTP ${r.status}`);
    }
  }

  log('info', `Content discovery complete — ${hits} interesting path(s) found.`);
  if (hits === 0) {
    finding({
      category: 'Configuration Management', title: 'Content discovery',
      status: 'pass', severity: 'info',
      evidence: `No unexpected paths found among ${words.length} candidates.`,
      remediation: 'No action required.', reference: REF,
    });
  }
}

module.exports = { id: 'fuzzer', category: 'Configuration Management', run };
