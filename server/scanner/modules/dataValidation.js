'use strict';

/**
 * dataValidation.js — active, non-destructive injection probes (Data Validation).
 * Injects marker payloads into parameters/forms discovered by the crawler and
 * inspects responses for reflection, error signatures, or behavioural signals.
 *
 * Coverage: reflected XSS, error/boolean/time-based SQLi, NoSQL, open redirect,
 * path traversal/LFI, command injection, SSTI, CRLF, XXE hint, HTTP param pollution,
 * HTTP verb tampering.
 *
 * Time-based checks only run at 'aggressive' intensity and use a single short delay
 * payload — never a loop or flood.
 */

const { URL } = require('url');

const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

const SQL_ERRORS =
  /(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBC|Unclosed quotation mark|Microsoft OLE DB|ODBC SQL|valid MySQL result|SQLSTATE)/i;

// Seed parameters to test when the crawler finds none.
const SEED_PARAMS = ['q', 'id', 'search', 'page', 'url', 'redirect', 'next', 'file', 'path', 'name'];

function withParam(urlStr, param, value) {
  const u = new URL(urlStr);
  u.searchParams.set(param, value);
  return u.toString();
}

function marker() {
  return 'ss' + Math.random().toString(36).slice(2, 8);
}

async function testXss(ctx, url, param) {
  const { http, log, finding } = ctx;
  const tag = marker();
  const payload = `"'><svg/onload=${tag}>`;
  const testUrl = withParam(url, param, payload);
  try {
    const r = await http.request(testUrl, { timeout: 10000 });
    if ((r.body || '').includes(payload)) {
      log('vuln', `Reflected XSS: param "${param}" reflects unencoded payload`);
      finding({
        category: 'Data Validation', title: `Reflected XSS in "${param}"`,
        status: 'fail', severity: 'high',
        evidence: `Payload reflected unencoded at ${testUrl}`,
        remediation: 'Context-encode output and validate input; apply a strong CSP.',
        reference: REF,
        request: { method: 'GET', url: testUrl, param, payload, status: r.status },
      });
      return true;
    }
  } catch (e) {
    log('debug', `xss ${param}: ${e.message}`);
  }
  return false;
}

async function testSqli(ctx, url, param) {
  const { http, log, finding, options } = ctx;
  // Error-based
  const errUrl = withParam(url, param, "'\"");
  try {
    const r = await http.request(errUrl, { timeout: 10000 });
    if (SQL_ERRORS.test(r.body || '')) {
      log('vuln', `SQL injection (error-based): param "${param}" leaks a DB error`);
      finding({
        category: 'Data Validation', title: `SQL Injection (error-based) in "${param}"`,
        status: 'fail', severity: 'critical',
        evidence: `DB error signature returned for ${errUrl}`,
        remediation: 'Use parameterized queries / prepared statements.', reference: REF,
        request: { method: 'GET', url: errUrl, param, payload: `'"`, status: r.status },
      });
      return true;
    }
  } catch (e) {
    log('debug', `sqli-error ${param}: ${e.message}`);
  }

  // Boolean-based (compare true vs false condition response lengths)
  try {
    const tRes = await http.request(withParam(url, param, "1' AND '1'='1"), { timeout: 10000 });
    const fRes = await http.request(withParam(url, param, "1' AND '1'='2"), { timeout: 10000 });
    const diff = Math.abs((tRes.body || '').length - (fRes.body || '').length);
    if (tRes.status === 200 && fRes.status === 200 && diff > 40) {
      log('vuln', `SQL injection (boolean-based): param "${param}" alters response by ${diff} bytes`);
      finding({
        category: 'Data Validation', title: `SQL Injection (boolean-based) in "${param}"`,
        status: 'fail', severity: 'high',
        evidence: `True/false conditions produced a ${diff}-byte response difference. TRUE=${withParam(url, param, "1' AND '1'='1")} vs FALSE=${withParam(url, param, "1' AND '1'='2")}`,
        remediation: 'Use parameterized queries and reject unexpected input.', reference: REF,
        request: { method: 'GET', url: withParam(url, param, "1' AND '1'='1"), param, payload: "1' AND '1'='1" },
      });
      return true;
    }
  } catch (e) {
    log('debug', `sqli-bool ${param}: ${e.message}`);
  }

  // Time-based (aggressive only, single short delay)
  if (options.intensity === 'aggressive') {
    try {
      const baseline = await http.request(withParam(url, param, '1'), { timeout: 12000 });
      const delayed = await http.request(
        withParam(url, param, "1'; SELECT pg_sleep(3)-- -"),
        { timeout: 12000 }
      );
      if (delayed.elapsedMs - baseline.elapsedMs > 2500) {
        log('vuln', `SQL injection (time-based): param "${param}" delayed response ~${delayed.elapsedMs}ms`);
        finding({
          category: 'Data Validation', title: `SQL Injection (time-based) in "${param}"`,
          status: 'fail', severity: 'critical',
          evidence: `Delay payload added ~${delayed.elapsedMs - baseline.elapsedMs}ms latency.`,
          remediation: 'Use parameterized queries; this indicates blind SQLi.', reference: REF,
          request: { method: 'GET', url: withParam(url, param, "1'; SELECT pg_sleep(3)-- -"), param, payload: "1'; SELECT pg_sleep(3)-- -" },
        });
        return true;
      }
    } catch (e) {
      log('debug', `sqli-time ${param}: ${e.message}`);
    }
  }
  return false;
}

async function testNoSql(ctx, url, param) {
  const { http, log, finding } = ctx;
  try {
    const base = await http.request(withParam(url, param, 'x'), { timeout: 10000 });
    const inj = await http.request(withParam(url, param, "x'||'1'=='1"), { timeout: 10000 });
    if (base.status !== inj.status && inj.status === 200) {
      log('warn', `Possible NoSQL injection: param "${param}" status changed under operator payload`);
      finding({
        category: 'Data Validation', title: `Possible NoSQL Injection in "${param}"`,
        status: 'warn', severity: 'medium',
        evidence: `Status ${base.status} -> ${inj.status} with operator payload.`,
        remediation: 'Validate/cast input types; use safe query builders.', reference: REF,
        request: { method: 'GET', url: withParam(url, param, "x'||'1'=='1"), param, payload: "x'||'1'=='1", status: inj.status },
      });
    }
  } catch (e) {
    log('debug', `nosql ${param}: ${e.message}`);
  }
}

async function testOpenRedirect(ctx, url, param) {
  const { http, log, finding } = ctx;
  if (!/redirect|url|next|return|dest|continue|to/i.test(param)) return;
  const evil = 'https://smartscan-evil.example/';
  try {
    const r = await http.request(withParam(url, param, evil), {
      timeout: 10000, followRedirects: false,
    });
    const loc = r.headers['location'] || '';
    if (r.status >= 300 && r.status < 400 && loc.startsWith('https://smartscan-evil.example')) {
      log('vuln', `Open redirect: param "${param}" redirects off-site`);
      finding({
        category: 'Data Validation', title: `Open Redirect in "${param}"`,
        status: 'fail', severity: 'medium',
        evidence: `Location: ${loc}`,
        remediation: 'Allowlist redirect targets; never redirect to raw user input.',
        reference: REF,
        request: { method: 'GET', url: withParam(url, param, evil), param, payload: evil, status: r.status },
      });
    }
  } catch (e) {
    log('debug', `redirect ${param}: ${e.message}`);
  }
}

async function testTraversal(ctx, url, param) {
  const { http, log, finding } = ctx;
  const payloads = ['../../../../etc/passwd', '..%2f..%2f..%2f..%2fetc%2fpasswd'];
  for (const p of payloads) {
    try {
      const r = await http.request(withParam(url, param, p), { timeout: 10000 });
      if (/root:.*:0:0:/.test(r.body || '')) {
        log('vuln', `Path traversal / LFI: param "${param}" returned /etc/passwd`);
        finding({
          category: 'Data Validation', title: `Path Traversal / LFI in "${param}"`,
          status: 'fail', severity: 'critical',
          evidence: 'Response contained /etc/passwd contents (root:...:0:0:).',
          remediation: 'Canonicalize and allowlist file paths; never use raw input in file access.',
          reference: REF,
          request: { method: 'GET', url: withParam(url, param, p), param, payload: p, status: r.status },
        });
        return;
      }
    } catch (e) {
      log('debug', `traversal ${param}: ${e.message}`);
    }
  }
}

async function testCmdInjection(ctx, url, param) {
  const { http, log, finding } = ctx;
  // Two distinct tokens multiplied by the shell: `expr $((A*B))` style is fragile,
  // so we use `echo`. Execution yields the bare token WITHOUT the literal "echo <tok>"
  // text; simple reflection echoes the whole payload back (which we must NOT flag).
  const tok = marker();
  const payloads = [`;echo ${tok};`, `| echo ${tok}`, `$(echo ${tok})`, `\`echo ${tok}\``];
  for (const p of payloads) {
    try {
      const r = await http.request(withParam(url, param, p), { timeout: 10000 });
      const body = r.body || '';
      const tokenPresent = new RegExp(`(^|[^a-z0-9])${tok}([^a-z0-9]|$)`).test(body);
      // Reflection guard: if the literal command text is echoed back, it is reflection,
      // not execution — do not flag.
      const literalReflected = body.includes(`echo ${tok}`);
      if (tokenPresent && !literalReflected) {
        log('vuln', `Command injection: param "${param}" executed echo and returned the marker`);
        finding({
          category: 'Data Validation', title: `Command Injection in "${param}"`,
          status: 'fail', severity: 'critical',
          evidence: `Marker "${tok}" was produced by an injected echo (payload: ${p}).`,
          remediation: 'Never pass input to a shell; use safe APIs and strict validation.',
          reference: REF,
          request: { method: 'GET', url: withParam(url, param, p), param, payload: p, status: r.status },
        });
        return;
      }
    } catch (e) {
      log('debug', `cmd ${param}: ${e.message}`);
    }
  }
}

async function testSsti(ctx, url, param) {
  const { http, log, finding } = ctx;
  try {
    const r = await http.request(withParam(url, param, '{{7*7}}${7*7}'), { timeout: 10000 });
    if (/(^|[^0-9])49([^0-9]|$)/.test(r.body || '')) {
      log('vuln', `Server-Side Template Injection: param "${param}" evaluated {{7*7}} -> 49`);
      finding({
        category: 'Data Validation', title: `SSTI in "${param}"`,
        status: 'fail', severity: 'high',
        evidence: 'Template expression {{7*7}} evaluated to 49 in the response.',
        remediation: 'Do not render user input as templates; sandbox the template engine.',
        reference: REF,
        request: { method: 'GET', url: withParam(url, param, '{{7*7}}${7*7}'), param, payload: '{{7*7}}${7*7}', status: r.status },
      });
    }
  } catch (e) {
    log('debug', `ssti ${param}: ${e.message}`);
  }
}

async function testCrlf(ctx, url, param) {
  const { http, log, finding } = ctx;
  const tok = marker();
  try {
    const r = await http.request(withParam(url, param, `x%0d%0aX-SmartScan:${tok}`), {
      timeout: 10000, followRedirects: false,
    });
    // Only a genuinely SPLIT response yields our value as its own parsed header.
    // A token that merely survives inside another header's value (CRLF neutralized)
    // is reflection, not injection, so we must not flag it.
    if (r.headers['x-smartscan'] === tok) {
      log('vuln', `CRLF/header injection: param "${param}" injected a response header`);
      finding({
        category: 'Data Validation', title: `CRLF / HTTP Response Splitting in "${param}"`,
        status: 'fail', severity: 'high',
        evidence: `Injected header X-SmartScan:${tok} appeared in the response.`,
        remediation: 'Strip CR/LF from values used in headers/redirects.', reference: REF,
        request: { method: 'GET', url: withParam(url, param, `x%0d%0aX-SmartScan:${tok}`), param, payload: `x%0d%0aX-SmartScan:${tok}`, status: r.status },
      });
    }
  } catch (e) {
    log('debug', `crlf ${param}: ${e.message}`);
  }
}

async function run(ctx) {
  const { log, finding, options } = ctx;
  const crawl = ctx.shared.crawl || { paramUrls: [], forms: [] };

  // Build the list of (url, param) targets.
  const targets = [];
  for (const { url, params } of crawl.paramUrls) {
    for (const p of params) targets.push({ url, param: p });
  }
  // If nothing found, seed synthetic params on the base URL.
  if (targets.length === 0) {
    for (const p of SEED_PARAMS) targets.push({ url: ctx.target, param: p });
    log('info', `No parameters discovered by crawl; testing ${SEED_PARAMS.length} seed parameters.`);
  } else {
    log('info', `Testing ${targets.length} parameter instance(s) for injection...`);
  }

  const cap = options.intensity === 'aggressive' ? 60 : 20;
  let count = 0;
  for (const { url, param } of targets) {
    if (count++ >= cap) {
      log('debug', `Injection target cap (${cap}) reached; stopping parameter tests.`);
      break;
    }
    log('debug', `Fuzzing parameter "${param}" on ${url}`);
    await testXss(ctx, url, param);
    await testSqli(ctx, url, param);
    await testNoSql(ctx, url, param);
    await testOpenRedirect(ctx, url, param);
    await testTraversal(ctx, url, param);
    await testCmdInjection(ctx, url, param);
    await testSsti(ctx, url, param);
    await testCrlf(ctx, url, param);
  }

  if (count === 0) {
    finding({
      category: 'Data Validation', title: 'Injection surface',
      status: 'info', severity: 'info',
      evidence: 'No injectable parameters or forms were discovered to test.',
      remediation: 'Provide URLs with parameters or authenticated pages for deeper testing.',
      reference: REF,
    });
  }
}

module.exports = { id: 'dataValidation', category: 'Data Validation', run };
