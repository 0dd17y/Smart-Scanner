'use strict';

/**
 * dos.js — AGGRESSIVE ONLY. Anti-automation / rate-limiting check (Denial of Service).
 * Sends a BOUNDED burst of requests (options.dosRequests, hard-capped) to see whether
 * the target throttles or blocks automated traffic. This is a detection probe, not a
 * flood: total volume is small and finite.
 */

const { URL } = require('url');

const REF =
  'https://owasp.org/www-project-web-security-testing-guide/';

async function run(ctx) {
  const { http, target, log, finding, options } = ctx;
  if (options.intensity !== 'aggressive') {
    log('debug', 'Rate-limit stress skipped (requires Aggressive intensity).');
    return;
  }

  // Prefer a login endpoint if we found one, else the base URL.
  const loginForms = ctx.shared.loginForms || [];
  const endpoint = loginForms.length ? loginForms[0].action : target;
  const total = Math.min(Math.max(options.dosRequests || 30, 5), 200); // bounded 5..200
  log('info', `Anti-automation probe: sending ${total} bounded requests to ${endpoint} ...`);

  let throttled = 0;
  let ok = 0;
  let errors = 0;
  const latencies = [];

  const tasks = [];
  for (let i = 0; i < total; i++) {
    tasks.push(
      http
        .request(endpoint, { timeout: 10000, followRedirects: false })
        .then((r) => {
          latencies.push(r.elapsedMs);
          if (r.status === 429 || r.status === 503) throttled++;
          else ok++;
        })
        .catch(() => {
          errors++;
        })
    );
  }
  await Promise.all(tasks);

  const avg = latencies.length
    ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
    : 0;
  log('debug', `Sent ${total}: ok=${ok} throttled=${throttled} errors=${errors} avgLatency=${avg}ms`);

  if (throttled > 0) {
    log('ok', `Server throttled ${throttled}/${total} requests (anti-automation active)`);
    finding({
      category: 'Denial of Service', title: 'Anti-automation / rate limiting present',
      status: 'pass', severity: 'info',
      evidence: `${throttled}/${total} requests received HTTP 429/503.`,
      remediation: 'No action required.', reference: REF,
    });
  } else {
    log('vuln', `No throttling observed across ${total} rapid requests`);
    finding({
      category: 'Denial of Service', title: 'No anti-automation / rate limiting',
      status: 'fail', severity: 'medium',
      evidence: `${total} rapid requests to ${endpoint} all served without throttling (avg ${avg}ms).`,
      remediation:
        'Add rate limiting / anti-automation controls (per-IP throttling, CAPTCHA, WAF).',
      reference: REF,
      request: { method: 'GET', url: endpoint, payload: `${total} rapid requests (no 429/503)` },
    });
  }
}

module.exports = { id: 'dos', category: 'Denial of Service', run };
