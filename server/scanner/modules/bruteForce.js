'use strict';

/**
 * bruteForce.js — AGGRESSIVE ONLY. Credential / default-credential attempts against
 * discovered login forms, and a check for brute-force protection (lockout / rate limit).
 *
 * Bounded by options.maxBruteAttempts (finite; no unbounded loops). Success detection
 * is heuristic (diff against a known-bad baseline), because it is application-specific.
 */

const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const REF =
  'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html';

function loadCreds(maxAttempts) {
  const file = path.join(__dirname, '..', 'wordlists', 'creds.txt');
  let lines = [];
  try {
    lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter((l) => l && !l.startsWith('#'));
  } catch {
    lines = ['admin:admin', 'admin:password', 'root:root', 'test:test'];
  }
  return lines.slice(0, maxAttempts).map((l) => {
    const idx = l.indexOf(':');
    return { user: l.slice(0, idx), pass: l.slice(idx + 1) };
  });
}

function fieldNames(form) {
  const pw = form.inputs.find((i) => i.type === 'password');
  const userField =
    form.inputs.find((i) => /user|email|login|name/i.test(i.name) && i.type !== 'password') ||
    form.inputs.find((i) => i.type === 'text' || i.type === 'email');
  return { userField: userField && userField.name, passField: pw && pw.name, form };
}

function buildBody(form, values) {
  const params = new URLSearchParams();
  for (const i of form.inputs) {
    if (values[i.name] != null) params.set(i.name, values[i.name]);
    else if (i.value) params.set(i.name, i.value);
    else params.set(i.name, '');
  }
  return params.toString();
}

async function submit(ctx, form, values) {
  const { http } = ctx;
  const body = buildBody(form, values);
  const method = form.method === 'POST' ? 'POST' : 'GET';
  if (method === 'GET') {
    const u = new URL(form.action);
    for (const [k, v] of new URLSearchParams(body)) u.searchParams.set(k, v);
    return http.request(u.toString(), { timeout: 10000, followRedirects: false });
  }
  return http.request(form.action, {
    method: 'POST',
    timeout: 10000,
    followRedirects: false,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
}

async function run(ctx) {
  const { log, finding, options } = ctx;
  if (options.intensity !== 'aggressive') {
    log('debug', 'Brute-force skipped (requires Aggressive intensity).');
    return;
  }

  const loginForms = ctx.shared.loginForms || [];
  if (!loginForms.length) {
    log('info', 'Brute-force: no login forms to target.');
    return;
  }

  const maxAttempts = Math.min(options.maxBruteAttempts || 25, 200);
  const creds = loadCreds(maxAttempts);
  log('info', `Brute-force: ${creds.length} credential pairs against ${loginForms.length} form(s) (cap ${maxAttempts}).`);

  for (const rawForm of loginForms) {
    const { userField, passField, form } = fieldNames(rawForm);
    if (!passField) {
      log('debug', 'Form has no identifiable password field; skipping.');
      continue;
    }

    // Baseline: a definitely-wrong credential.
    let baseline;
    try {
      baseline = await submit(ctx, form, {
        [userField || 'username']: 'smartscan_nouser_' + Date.now(),
        [passField]: 'wrongpassword_' + Date.now(),
      });
    } catch (e) {
      log('warn', `Brute-force baseline failed: ${e.message}`);
      continue;
    }
    const baseLen = (baseline.body || '').length;
    log('debug', `Baseline (bad creds): HTTP ${baseline.status}, ${baseLen} bytes`);

    let throttled = false;
    let attempts = 0;
    let possibleValid = null;

    for (const c of creds) {
      attempts++;
      let r;
      try {
        r = await submit(ctx, form, {
          [userField || 'username']: c.user,
          [passField]: c.pass,
        });
      } catch (e) {
        log('debug', `attempt ${c.user}:${c.pass} error ${e.message}`);
        continue;
      }

      if (r.status === 429 || r.status === 503) {
        throttled = true;
        log('ok', `Server throttled after ${attempts} attempt(s) (HTTP ${r.status})`);
        break;
      }

      const lenDiff = Math.abs((r.body || '').length - baseLen);
      const redirected = r.status >= 300 && r.status < 400;
      const looksValid =
        (redirected && !(baseline.status >= 300 && baseline.status < 400)) ||
        (r.status === 200 && lenDiff > 60 && !/invalid|incorrect|failed|denied/i.test(r.body || ''));

      if (looksValid) {
        possibleValid = c;
        log('vuln', `Possible valid credential: ${c.user}:${c.pass} (HTTP ${r.status})`);
        break;
      }
      log('debug', `tried ${c.user}:${c.pass} -> HTTP ${r.status}, diff ${lenDiff}`);
    }

    if (possibleValid) {
      finding({
        category: 'Authentication', title: 'Weak / default credentials accepted',
        status: 'fail', severity: 'critical',
        evidence: `Login form ${form.action} appears to accept ${possibleValid.user}:${possibleValid.pass}.`,
        remediation: 'Remove default accounts; enforce strong password policy and MFA.',
        reference: REF,
        request: { method: form.method || 'POST', url: form.action, payload: `${possibleValid.user}:${possibleValid.pass}` },
      });
    }

    if (!throttled) {
      log('vuln', `No lockout/throttling after ${attempts} login attempts`);
      finding({
        category: 'Authentication', title: 'No brute-force protection',
        status: 'fail', severity: 'high',
        evidence: `${attempts} rapid login attempts on ${form.action} without lockout or rate limiting.`,
        remediation: 'Add account lockout, rate limiting, and CAPTCHA after failed attempts.',
        reference: REF,
        request: { method: form.method || 'POST', url: form.action, payload: `${attempts} rapid login attempts` },
      });
    } else {
      finding({
        category: 'Authentication', title: 'Brute-force protection present',
        status: 'pass', severity: 'info',
        evidence: `Requests were throttled during the attempt sequence.`,
        remediation: 'No action required.', reference: REF,
      });
    }
  }
}

module.exports = { id: 'bruteForce', category: 'Authentication', run };
