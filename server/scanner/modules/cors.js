'use strict';

/**
 * cors.js — CORS misconfiguration probe (HTML5 / Configuration).
 * Sends a crafted Origin and inspects the reflection + credentials flag.
 */

const REF =
  'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html';

async function run(ctx) {
  const { http, target, log, finding } = ctx;
  const evilOrigin = 'https://smartscan-evil.example';
  log('info', `Sending Origin: ${evilOrigin} to test CORS reflection...`);

  let res;
  try {
    res = await http.request(target, {
      timeout: 12000,
      headers: { Origin: evilOrigin },
    });
  } catch (e) {
    log('warn', `CORS probe failed: ${e.message}`);
    return;
  }

  const acao = res.headers['access-control-allow-origin'];
  const acac = res.headers['access-control-allow-credentials'];
  const req = { method: 'GET', url: target, headers: { Origin: evilOrigin }, payload: `Origin: ${evilOrigin}`, status: res.status };
  log('debug', `ACAO=${acao || '(none)'} ACAC=${acac || '(none)'}`);

  if (!acao) {
    log('ok', 'No Access-Control-Allow-Origin header (CORS not exposing resources here)');
    finding({
      category: 'HTML 5', title: 'CORS policy',
      status: 'pass', severity: 'info', evidence: 'No ACAO header returned.',
      remediation: 'No action required.', reference: REF,
    });
    return;
  }

  const reflectsEvil = acao === evilOrigin;
  const wildcard = acao === '*';
  const withCreds = String(acac).toLowerCase() === 'true';

  if (reflectsEvil && withCreds) {
    log('vuln', 'CORS reflects arbitrary Origin AND allows credentials — critical misconfig');
    finding({
      category: 'HTML 5', title: 'CORS reflects arbitrary origin with credentials',
      status: 'fail', severity: 'high',
      evidence: `ACAO reflected ${evilOrigin} with Allow-Credentials: true.`,
      remediation:
        'Never reflect arbitrary origins with credentials; use a strict allowlist.',
      reference: REF, request: req,
    });
  } else if (reflectsEvil) {
    log('vuln', 'CORS reflects arbitrary Origin');
    finding({
      category: 'HTML 5', title: 'CORS reflects arbitrary origin',
      status: 'fail', severity: 'medium',
      evidence: `ACAO reflected the attacker-supplied origin ${evilOrigin}.`,
      remediation: 'Validate Origin against a strict allowlist instead of reflecting it.',
      reference: REF, request: req,
    });
  } else if (wildcard && withCreds) {
    log('vuln', 'ACAO:* combined with Allow-Credentials (invalid + risky)');
    finding({
      category: 'HTML 5', title: 'CORS wildcard with credentials',
      status: 'fail', severity: 'medium',
      evidence: 'Access-Control-Allow-Origin: * with Allow-Credentials: true.',
      remediation: 'Do not combine wildcard origin with credentials.', reference: REF, request: req,
    });
  } else if (wildcard) {
    log('warn', 'ACAO is wildcard (*)');
    finding({
      category: 'HTML 5', title: 'CORS wildcard origin',
      status: 'warn', severity: 'low',
      evidence: 'Access-Control-Allow-Origin: *',
      remediation: 'Restrict CORS to the specific origins that need access.', reference: REF, request: req,
    });
  } else {
    log('ok', `CORS restricted to ${acao}`);
    finding({
      category: 'HTML 5', title: 'CORS restricted',
      status: 'pass', severity: 'info', evidence: `ACAO=${acao}`,
      remediation: 'No action required.', reference: REF,
    });
  }
}

module.exports = { id: 'cors', category: 'HTML 5', run };
