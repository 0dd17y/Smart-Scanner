'use strict';

/**
 * session.js — cookie / session token analysis (Session Management).
 */

const { URL } = require('url');

const REF =
  'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html';

function parseCookie(raw) {
  const parts = raw.split(';').map((p) => p.trim());
  const [nv] = parts;
  const eq = nv.indexOf('=');
  const name = eq >= 0 ? nv.slice(0, eq) : nv;
  const value = eq >= 0 ? nv.slice(eq + 1) : '';
  const attrs = {};
  for (const p of parts.slice(1)) {
    const [k, v] = p.split('=');
    attrs[k.toLowerCase()] = v == null ? true : v;
  }
  return { name, value, attrs };
}

// crude Shannon-entropy-per-char to flag low-randomness tokens
function entropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const c in freq) {
    const p = freq[c] / str.length;
    h -= p * Math.log2(p);
  }
  return h * str.length;
}

async function run(ctx) {
  const { http, target, log, finding } = ctx;
  const isHttps = new URL(target).protocol === 'https:';

  let res = ctx.shared.baseResponse;
  if (!res) {
    try {
      res = await http.request(target, { timeout: 12000 });
    } catch (e) {
      log('warn', `Session check could not fetch target: ${e.message}`);
      return;
    }
  }

  const cookies = res.setCookies || [];
  if (!cookies.length) {
    log('info', 'No cookies set on the initial response.');
    finding({
      category: 'Session Management', title: 'Cookies',
      status: 'info', severity: 'info', evidence: 'No Set-Cookie headers observed.',
      remediation: 'If sessions are used, ensure cookies carry Secure, HttpOnly and SameSite.',
      reference: REF,
    });
    return;
  }

  log('info', `Analyzing ${cookies.length} cookie(s)...`);
  for (const raw of cookies) {
    const { name, value, attrs } = parseCookie(raw);
    const looksSession = /sess|sid|token|auth|jsession|phpsessid|asp\.net/i.test(name);
    log('debug', `Cookie ${name} — flags: ${Object.keys(attrs).join(', ') || 'none'}`);

    const issues = [];
    if (!attrs.secure && isHttps) issues.push('missing Secure');
    if (!attrs.httponly) issues.push('missing HttpOnly');
    if (!attrs.samesite) issues.push('missing SameSite');

    if (issues.length) {
      const sev = looksSession ? 'high' : 'medium';
      log('vuln', `Cookie ${name}: ${issues.join(', ')}`);
      finding({
        category: 'Session Management',
        title: `Insecure cookie flags: ${name}`,
        status: 'fail', severity: sev,
        evidence: `${raw}\nIssues: ${issues.join(', ')}`,
        remediation:
          'Set Secure, HttpOnly and SameSite on session cookies; scope Path/Domain tightly.',
        reference: REF,
      });
    } else {
      log('ok', `Cookie ${name}: Secure + HttpOnly + SameSite present`);
      finding({
        category: 'Session Management', title: `Cookie flags OK: ${name}`,
        status: 'pass', severity: 'info', evidence: raw,
        remediation: 'No action required.', reference: REF,
      });
    }

    // duration
    if (looksSession && (attrs['max-age'] || attrs.expires)) {
      log('warn', `Session cookie ${name} is persistent (has expiry/max-age)`);
      finding({
        category: 'Session Management', title: `Persistent session cookie: ${name}`,
        status: 'warn', severity: 'low',
        evidence: `max-age=${attrs['max-age'] || ''} expires=${attrs.expires || ''}`,
        remediation: 'Prefer short-lived session cookies without long persistence.',
        reference: REF,
      });
    }

    // randomness
    if (looksSession && value) {
      const e = entropy(value);
      log('debug', `Token ${name} entropy ~${e.toFixed(1)} bits over ${value.length} chars`);
      if (e < 40) {
        log('vuln', `Session token ${name} appears low-entropy (~${e.toFixed(0)} bits)`);
        finding({
          category: 'Session Management', title: `Low-entropy session token: ${name}`,
          status: 'fail', severity: 'medium',
          evidence: `Estimated entropy ~${e.toFixed(0)} bits; value length ${value.length}.`,
          remediation: 'Generate session identifiers from a CSPRNG with >=128 bits of entropy.',
          reference: REF,
        });
      }
    }
  }
}

module.exports = { id: 'session', category: 'Session Management', run };
