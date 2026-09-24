'use strict';

/**
 * dosAdvanced.js — AGGRESSIVE. Bounded resource-abuse probes (checks 49-50).
 * These are single, finite requests — detection probes, never floods.
 */

const { URL } = require('url');
const P = require('../probeUtils');
const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

function fire(ctx, f) { ctx.finding({ category: 'Denial of Service', reference: REF, ...f }); }

// 49. large-payload / body-limit tolerance (single bounded oversized body)
async function largePayload(ctx) {
  const { log, options } = ctx;
  const kb = Math.min(Math.max(options.maxBodyKb || 1024, 64), 5120); // 64KB..5MB
  const body = 'A'.repeat(kb * 1024);
  const forms = P.loginForms(ctx).concat((ctx.shared.crawl && ctx.shared.crawl.forms) || []);
  const target = forms.length ? forms[0].action : ctx.target;
  const fieldName = forms.length && P.fieldNames(forms[0]).userField ? P.fieldNames(forms[0]).userField : 'data';
  try {
    const r = await ctx.http.request(target, {
      method: 'POST', timeout: 15000, followRedirects: false,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `${encodeURIComponent(fieldName)}=${body}`,
      maxBodyBytes: 2000000,
    });
    if (r.status === 413 || r.status === 431) {
      log('ok', `Server enforces a request body limit (HTTP ${r.status})`);
    } else if (r.status < 500) {
      log('warn', `Server accepted a ${kb}KB body without a size limit (HTTP ${r.status})`);
      fire(ctx, { title: 'No request body-size limit', status: 'warn', severity: 'low',
        evidence: `A ${kb}KB POST body to ${target} was accepted (HTTP ${r.status}) with no 413/431 — memory/DoS exposure.`,
        remediation: 'Enforce a maximum request body size at the proxy/app layer.',
        request: { method: 'POST', url: target, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${encodeURIComponent(fieldName)}=AAAA…(${kb}KB)`, payload: `${kb}KB body`, status: r.status } });
    } else {
      log('warn', `Large body caused a server error (HTTP ${r.status})`);
      fire(ctx, { title: 'Large request body causes server error', status: 'warn', severity: 'medium',
        evidence: `A ${kb}KB body to ${target} produced HTTP ${r.status}.`,
        remediation: 'Reject oversized bodies gracefully with 413 before processing.',
        request: { method: 'POST', url: target, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${encodeURIComponent(fieldName)}=AAAA…(${kb}KB)`, payload: `${kb}KB body`, status: r.status } });
    }
  } catch (e) {
    log('debug', `largePayload: ${e.message}`);
  }
}

// 50. ReDoS / algorithmic complexity on search-like params (bounded timing)
async function redos(ctx) {
  const { log } = ctx;
  // A classic catastrophic-backtracking trigger; bounded single request.
  const evil = 'a'.repeat(40) + '!';
  const nested = '(' .repeat(0) + 'a'.repeat(30) + 'X';
  for (const { url, param } of P.paramTargets(ctx, 8)) {
    if (!/q|search|filter|query|name|email|term|keyword/i.test(param)) continue;
    try {
      const baseline = (await P.timedRequest(ctx, P.withParam(url, param, 'abc'))).ms;
      const t1 = (await P.timedRequest(ctx, P.withParam(url, param, evil))).ms;
      const t2 = (await P.timedRequest(ctx, P.withParam(url, param, nested))).ms;
      const worst = Math.max(t1, t2);
      if (worst - baseline > 4000) {
        log('vuln', `Possible ReDoS on "${param}": +${worst - baseline}ms`);
        fire(ctx, { title: `Possible ReDoS / algorithmic complexity in "${param}"`, status: 'fail', severity: 'medium',
          evidence: `A crafted input delayed the response by ~${worst - baseline}ms vs baseline — likely catastrophic regex backtracking.`,
          remediation: 'Avoid vulnerable regex; use linear-time engines (RE2), input length caps, and timeouts.',
          request: { method: 'GET', url: P.withParam(url, param, evil), param, payload: evil } });
        return;
      }
    } catch (e) { log('debug', `redos: ${e.message}`); }
  }
}

async function run(ctx) {
  if (ctx.options.intensity !== 'aggressive') {
    ctx.log('debug', 'Advanced DoS skipped (requires Aggressive intensity).');
    return;
  }
  ctx.log('info', 'Advanced DoS (bounded): request body-size limit, ReDoS/algorithmic complexity...');
  for (const [name, fn] of [['large payload', largePayload], ['ReDoS', redos]]) {
    ctx.log('debug', `→ ${name}`);
    try { await fn(ctx); } catch (e) { ctx.log('debug', `${name} error: ${e.message}`); }
  }
}

module.exports = { id: 'dosAdvanced', category: 'Denial of Service', run };
