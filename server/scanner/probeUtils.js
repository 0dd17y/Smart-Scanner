'use strict';

/**
 * probeUtils.js — shared primitives for the aggressive attack modules.
 * Consolidates parameter/form injection helpers, cookie/JWT parsing, entropy,
 * timing, and common signature regexes so the new modules stay small and consistent.
 */

const crypto = require('crypto');
const { URL } = require('url');

// ---- markers & param rewriting --------------------------------------------
function marker(prefix) {
  return (prefix || 'ss') + Math.random().toString(36).slice(2, 9);
}

function withParam(urlStr, param, value) {
  const u = new URL(urlStr);
  u.searchParams.set(param, value);
  return u.toString();
}

const SEED_PARAMS = ['q', 'id', 'search', 'page', 'url', 'redirect', 'next', 'file', 'path', 'name', 'user', 'view', 'lang'];

/**
 * Build the list of {url, param} injection targets from the crawl. Falls back to
 * seeding synthetic params on the base target when the crawl found none.
 */
function paramTargets(ctx, cap) {
  const crawl = ctx.shared.crawl || { paramUrls: [] };
  const targets = [];
  for (const { url, params } of crawl.paramUrls) {
    for (const p of params) targets.push({ url, param: p });
  }
  if (targets.length === 0) {
    for (const p of SEED_PARAMS) targets.push({ url: ctx.target, param: p });
  }
  return typeof cap === 'number' ? targets.slice(0, cap) : targets;
}

function forms(ctx) {
  return (ctx.shared.crawl && ctx.shared.crawl.forms) || [];
}

// ---- form submission ------------------------------------------------------
function buildBody(form, values) {
  const params = new URLSearchParams();
  for (const i of form.inputs) {
    if (values[i.name] != null) params.set(i.name, values[i.name]);
    else if (i.value) params.set(i.name, i.value);
    else params.set(i.name, '');
  }
  // extra (non-form) fields, e.g. mass-assignment injections
  for (const k of Object.keys(values)) {
    if (!form.inputs.some((i) => i.name === k)) params.set(k, values[k]);
  }
  return params.toString();
}

async function submitForm(ctx, form, values, opts = {}) {
  const { http } = ctx;
  const body = buildBody(form, values);
  const method = (form.method === 'POST' ? 'POST' : 'GET');
  if (method === 'GET') {
    const u = new URL(form.action);
    for (const [k, v] of new URLSearchParams(body)) u.searchParams.set(k, v);
    return http.request(u.toString(), { timeout: 10000, followRedirects: false, ...opts });
  }
  return http.request(form.action, {
    method: 'POST',
    timeout: 10000,
    followRedirects: false,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(opts.headers || {}) },
    body,
    ...opts,
  });
}

function loginForms(ctx) {
  const explicit = ctx.shared.loginForms;
  if (explicit && explicit.length) return explicit;
  return forms(ctx).filter((f) => f.inputs.some((i) => i.type === 'password'));
}

function fieldNames(form) {
  const pw = form.inputs.find((i) => i.type === 'password');
  const userField =
    form.inputs.find((i) => /user|email|login|name/i.test(i.name) && i.type !== 'password') ||
    form.inputs.find((i) => i.type === 'text' || i.type === 'email');
  return { userField: userField && userField.name, passField: pw && pw.name };
}

// ---- cookies & JWT --------------------------------------------------------
function parseCookie(raw) {
  const parts = raw.split(';').map((p) => p.trim());
  const nv = parts[0] || '';
  const eq = nv.indexOf('=');
  return { name: eq >= 0 ? nv.slice(0, eq) : nv, value: eq >= 0 ? nv.slice(eq + 1) : '' };
}

function cookiesFrom(res) {
  return (res && res.setCookies ? res.setCookies : []).map(parseCookie);
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try { return Buffer.from(s, 'base64').toString('utf8'); } catch { return ''; }
}
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const JWT_RE = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/;

// Find a JWT anywhere in cookies, headers, or body.
function findJwt(res) {
  const hay = [];
  for (const c of cookiesFrom(res)) hay.push(c.value);
  if (res && res.headers) {
    if (res.headers['authorization']) hay.push(res.headers['authorization']);
    hay.push(JSON.stringify(res.headers));
  }
  if (res && res.body) hay.push(res.body.slice(0, 40000));
  for (const h of hay) {
    const m = JWT_RE.exec(h || '');
    if (m) return m[0];
  }
  return null;
}

function decodeJwt(token) {
  const [h, p] = token.split('.');
  let header = {}, payload = {};
  try { header = JSON.parse(b64urlDecode(h)); } catch { /* */ }
  try { payload = JSON.parse(b64urlDecode(p)); } catch { /* */ }
  return { header, payload };
}

function signHs256(headerObj, payloadObj, secret) {
  const h = b64url(JSON.stringify(headerObj));
  const p = b64url(JSON.stringify(payloadObj));
  const data = `${h}.${p}`;
  const sig = b64url(crypto.createHmac('sha256', secret).update(data).digest());
  return `${data}.${sig}`;
}

// verify a token's HS256 signature against a candidate secret
function verifyHs256(token, secret) {
  const [h, p, sig] = token.split('.');
  if (!sig) return false;
  const expect = b64url(crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest());
  return expect === sig;
}

// ---- entropy --------------------------------------------------------------
function entropyBits(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const c in freq) {
    const pr = freq[c] / str.length;
    h -= pr * Math.log2(pr);
  }
  return h * str.length;
}

// ---- timing ---------------------------------------------------------------
async function timedRequest(ctx, url, opts) {
  const r = await ctx.http.request(url, { timeout: 15000, ...opts });
  return { res: r, ms: r.elapsedMs };
}

// ---- reproduction: build a runnable curl from a request descriptor --------
function shq(s) {
  // single-quote for POSIX shells, escaping embedded single quotes
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}
function toCurl(request) {
  if (!request || !request.url) return null;
  const method = (request.method || 'GET').toUpperCase();
  const parts = ['curl', '-i', '-sk'];
  if (method !== 'GET') parts.push('-X', method);
  const headers = request.headers || {};
  for (const k of Object.keys(headers)) {
    parts.push('-H', shq(`${k}: ${headers[k]}`));
  }
  if (request.body != null && request.body !== '') {
    if (!headers['Content-Type'] && !headers['content-type'] && method !== 'GET') {
      parts.push('-H', shq('Content-Type: application/x-www-form-urlencoded'));
    }
    parts.push('--data', shq(request.body));
  }
  parts.push(shq(request.url));
  return parts.join(' ');
}

// Build a human-readable URL where the injected param's value is the RAW payload
// (not percent-encoded), so it's easy to read and edit when reproducing.
function toDisplayUrl(request) {
  if (!request || !request.url) return null;
  if (request.param == null || request.payload == null) return request.url;
  try {
    const u = new URL(request.url);
    if (!u.searchParams.has(request.param)) return request.url; // param is in body/header, not query
    const parts = [];
    for (const [k, v] of u.searchParams.entries()) {
      parts.push(k === request.param ? `${k}=${request.payload}` : `${k}=${v}`);
    }
    return `${u.origin}${u.pathname}?${parts.join('&')}${u.hash}`;
  } catch {
    return request.url;
  }
}

// ---- shared signatures ----------------------------------------------------
const SIGS = {
  sqlError: /(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBC|Unclosed quotation mark|Microsoft OLE DB|ODBC SQL|valid MySQL result|SQLSTATE)/i,
  ldapError: /(LDAP: error code|javax\.naming|com\.sun\.jndi|Invalid DN syntax|IN_SUBTREE)/i,
  xpathError: /(XPath|xmlXPathEval|SimpleXMLElement|xpath_eval|Expression must evaluate)/i,
  passwd: /root:.*?:0:0:/,
  denial: /access denied|you don'?t have permission|not authorized|request rejected|forbidden|edgesuite\.net|akamai|cloudflare|blocked|captcha|mod_security/i,
  metadata: /ami-id|instance-id|iam\/security-credentials|computeMetadata|"AccessKeyId"|meta-data/i,
  takeover: /NoSuchBucket|There isn't a GitHub Pages site here|no such app|Fastly error: unknown domain|herokucdn\.com\/error|The specified bucket does not exist|Repository not found|Sorry, this shop is currently unavailable|project not found|Domain uses DO/i,
};

module.exports = {
  marker, withParam, SEED_PARAMS, paramTargets, forms, loginForms, fieldNames,
  buildBody, submitForm, parseCookie, cookiesFrom, findJwt, decodeJwt,
  signHs256, verifyHs256, b64url, b64urlDecode, entropyBits, timedRequest, toCurl, toDisplayUrl, SIGS,
};
