'use strict';

/**
 * authentication.js — login form posture (Authentication).
 * Detects login forms, autocomplete on password fields, password-over-HTTP,
 * and records discovered login forms for the brute-force module.
 */

const { URL } = require('url');

const REF =
  'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html';

function findLoginForms(forms) {
  return forms.filter((f) =>
    f.inputs.some((i) => i.type === 'password')
  );
}

async function run(ctx) {
  const { target, log, finding } = ctx;
  const crawl = ctx.shared.crawl || { forms: [] };
  const loginForms = findLoginForms(crawl.forms);
  ctx.shared.loginForms = loginForms;

  if (!loginForms.length) {
    log('info', 'No login forms (password fields) discovered.');
    finding({
      category: 'Authentication', title: 'Login form discovery',
      status: 'info', severity: 'info',
      evidence: 'No password-bearing forms found in the crawled surface.',
      remediation: 'Point the scanner at the login page for authentication testing.',
      reference: REF,
    });
    return;
  }

  log('info', `Discovered ${loginForms.length} login form(s).`);
  const targetHttps = new URL(target).protocol === 'https:';

  for (const f of loginForms) {
    const actionHttps = f.action.startsWith('https:');
    log('debug', `Login form action=${f.action} method=${f.method}`);

    // password over HTTPS
    if (!actionHttps) {
      log('vuln', `Login form submits over non-HTTPS: ${f.action}`);
      finding({
        category: 'Authentication', title: 'Credentials submitted over HTTP',
        status: 'fail', severity: 'high',
        evidence: `Form action ${f.action} is not HTTPS.`,
        remediation: 'Serve and submit all login forms exclusively over HTTPS.',
        reference: REF,
      });
    } else if (targetHttps) {
      finding({
        category: 'Authentication', title: 'Login form over HTTPS',
        status: 'pass', severity: 'info', evidence: f.action,
        remediation: 'No action required.', reference: REF,
      });
    }

    // autocomplete on password fields
    const pw = f.inputs.find((i) => i.type === 'password');
    // We only have name/type/value from the crawler; re-fetch to inspect autocomplete.
  }

  // Autocomplete inspection: re-fetch the page(s) holding password fields.
  try {
    const http = ctx.http;
    const res = ctx.shared.baseResponse || (await http.request(target, { timeout: 10000 }));
    const pwBlocks = (res.body || '').match(/<input[^>]*type=["']password["'][^>]*>/gi) || [];
    let missingAc = 0;
    for (const b of pwBlocks) {
      if (!/autocomplete\s*=\s*["'](off|new-password|current-password)["']/i.test(b)) {
        missingAc++;
      }
    }
    if (missingAc > 0) {
      log('warn', `${missingAc} password field(s) without autocomplete=off/new-password`);
      finding({
        category: 'Authentication', title: 'Password field autocomplete enabled',
        status: 'warn', severity: 'low',
        evidence: `${missingAc} password input(s) allow autocomplete.`,
        remediation: 'Set autocomplete="new-password"/"off" on sensitive password fields.',
        reference: REF,
      });
    } else if (pwBlocks.length) {
      log('ok', 'Password fields set autocomplete appropriately');
    }
  } catch (e) {
    log('debug', `autocomplete inspection failed: ${e.message}`);
  }
}

module.exports = { id: 'authentication', category: 'Authentication', run };
