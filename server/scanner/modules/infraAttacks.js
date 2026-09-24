'use strict';

/**
 * infraAttacks.js — AGGRESSIVE. Infrastructure & exposure checks (43-48). In-band only.
 */

const { URL } = require('url');
const P = require('../probeUtils');
const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

function fire(ctx, f) { ctx.finding({ category: 'Configuration Management', reference: REF, ...f }); }

// 43. actuator / debug / management endpoints
const DEBUG_ENDPOINTS = [
  { p: '/actuator/env', re: /"propertySources"|systemProperties/i, name: 'Spring actuator /env' },
  { p: '/actuator/health', re: /"status"\s*:\s*"UP"/i, name: 'Spring actuator /health' },
  { p: '/actuator/heapdump', re: /.{0,0}/, name: 'Spring actuator /heapdump', ctype: /octet-stream|hprof/i },
  { p: '/actuator', re: /_links|actuator/i, name: 'Spring actuator index' },
  { p: '/debug', re: /debug|traceback|stack/i, name: 'Debug endpoint' },
  { p: '/trace', re: /"timestamp"|traces/i, name: 'Spring /trace' },
  { p: '/phpinfo.php', re: /phpinfo\(\)|PHP Version/i, name: 'phpinfo' },
  { p: '/server-status', re: /Apache Server Status|Scoreboard/i, name: 'Apache server-status' },
  { p: '/.env', re: /^[A-Z0-9_]+=/m, name: '.env file' },
];
async function debugEndpoints(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const base = `${origin.protocol}//${origin.host}`;
  for (const e of DEBUG_ENDPOINTS) {
    try {
      const r = await ctx.http.request(base + e.p, { timeout: 8000 });
      if (r.status !== 200 || P.SIGS.denial.test(r.body || '')) continue;
      const ctypeOk = e.ctype ? e.ctype.test(r.headers['content-type'] || '') : true;
      if (ctypeOk && e.re.test(r.body || '')) {
        log('vuln', `Exposed management/debug endpoint: ${e.p}`);
        fire(ctx, { title: `Exposed endpoint: ${e.name} (${e.p})`, status: 'fail', severity: 'high',
          evidence: `${e.p} returned 200 with matching diagnostic content.`,
          remediation: 'Restrict/secure management, debug and actuator endpoints; never expose them publicly.',
          request: { method: 'GET', url: base + e.p, status: r.status } });
      }
    } catch (err) { log('debug', `debugep ${e.p}: ${err.message}`); }
  }
}

// 44. cloud metadata reachability via SSRF-style params
async function cloudMetadata(ctx) {
  const { log } = ctx;
  for (const { url, param } of P.paramTargets(ctx, 10)) {
    if (!/url|uri|host|target|proxy|fetch|callback|dest|domain|image|load/i.test(param)) continue;
    try {
      const r = await ctx.http.request(P.withParam(url, param, 'http://169.254.169.254/latest/meta-data/'), { timeout: 8000 });
      if (P.SIGS.metadata.test(r.body || '')) {
        log('vuln', `Cloud metadata reachable via "${param}"`);
        fire(ctx, { category: 'Data Validation', title: `Cloud metadata SSRF via "${param}"`, status: 'fail', severity: 'critical',
          evidence: `Response contained cloud instance-metadata after injecting the 169.254.169.254 endpoint.`,
          remediation: 'Block link-local ranges; require IMDSv2; allowlist outbound fetch destinations.',
          request: { method: 'GET', url: P.withParam(url, param, 'http://169.254.169.254/latest/meta-data/'), param, payload: 'http://169.254.169.254/latest/meta-data/', status: r.status } });
        return;
      }
    } catch (e) { /* */ }
  }
}

// 45. subdomain takeover fingerprint
async function subdomainTakeover(ctx) {
  const { log } = ctx;
  const res = ctx.shared.baseResponse;
  if (res && P.SIGS.takeover.test(res.body || '')) {
    log('vuln', 'Subdomain takeover fingerprint present in base response');
    fire(ctx, { title: 'Possible subdomain takeover', status: 'fail', severity: 'high',
      evidence: 'The site returns a known unclaimed-service error fingerprint (dangling DNS pointing to an unregistered service).',
      remediation: 'Remove dangling DNS records; reclaim or delete the referenced service resource.',
      request: { method: 'GET', url: ctx.target } });
  } else {
    log('ok', 'No subdomain-takeover fingerprint detected');
  }
}

// 46. VCS repo dump
async function vcsDump(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const base = `${origin.protocol}//${origin.host}`;
  const checks = [
    { p: '/.git/config', re: /\[core\]|\[remote|repositoryformatversion/i, name: '.git/config' },
    { p: '/.git/HEAD', re: /ref:\s*refs\//i, name: '.git/HEAD' },
    { p: '/.svn/entries', re: /^\d+|svn:|dir/i, name: '.svn/entries' },
    { p: '/.hg/requires', re: /revlogv1|dotencode|store/i, name: '.hg/requires' },
  ];
  for (const c of checks) {
    try {
      const r = await ctx.http.request(base + c.p, { timeout: 8000 });
      if (r.status === 200 && !P.SIGS.denial.test(r.body || '') && c.re.test(r.body || '')) {
        log('vuln', `Exposed VCS metadata: ${c.p}`);
        fire(ctx, { title: `Exposed VCS repository: ${c.name}`, status: 'fail', severity: 'high',
          evidence: `${c.p} is readable with matching content — source code may be reconstructable.`,
          remediation: 'Block access to .git/.svn/.hg directories at the web server; keep VCS out of the web root.',
          request: { method: 'GET', url: base + c.p, status: r.status } });
      }
    } catch (e) { /* */ }
  }
}

// 47. backup / source archive brute
async function backupArchives(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const base = `${origin.protocol}//${origin.host}`;
  const host = origin.hostname.split('.')[0];
  const names = ['backup', 'www', 'site', 'web', 'app', 'db', 'database', 'dump', host];
  const exts = ['.zip', '.tar.gz', '.sql', '.bak', '.tar', '.rar'];
  const ZIP = 'PK\x03\x04';
  let checked = 0;
  for (const n of names) {
    for (const e of exts) {
      if (checked++ > 30) return;
      try {
        const r = await ctx.http.request(`${base}/${n}${e}`, { timeout: 7000 });
        if (r.status === 200 && (r.body || '').length > 8 && !P.SIGS.denial.test(r.body || '')) {
          const looksArchive = (r.body || '').startsWith(ZIP) || /\x1f\x8b/.test((r.body || '').slice(0, 4)) ||
            /octet-stream|zip|gzip|sql/i.test(r.headers['content-type'] || '') || /INSERT INTO|CREATE TABLE/i.test(r.body || '');
          if (looksArchive) {
            log('vuln', `Downloadable backup/source archive: /${n}${e}`);
            fire(ctx, { title: `Exposed backup/source archive: /${n}${e}`, status: 'fail', severity: 'high',
              evidence: `/${n}${e} is downloadable and looks like an archive/DB dump.`,
              remediation: 'Remove backups/dumps from the web root; block archive extensions.',
              request: { method: 'GET', url: `${base}/${n}${e}`, status: r.status } });
            return;
          }
        }
      } catch (err) { /* */ }
    }
  }
}

// 48. virtual-host / host-routing bypass
async function vhostBypass(ctx) {
  const { log } = ctx;
  const origin = new URL(ctx.target);
  const base = `${origin.protocol}//${origin.host}`;
  try {
    const normal = ctx.shared.baseResponse || await ctx.http.request(ctx.target, { timeout: 8000 });
    for (const vh of ['localhost', 'internal', 'admin.' + origin.hostname, '127.0.0.1']) {
      const r = await ctx.http.request(base + '/', { timeout: 8000, headers: { Host: vh } });
      if (r.status === 200 && Math.abs((r.body || '').length - (normal.body || '').length) > 300 &&
          !P.SIGS.denial.test(r.body || '')) {
        log('warn', `Different app served for Host: ${vh}`);
        fire(ctx, { title: `Virtual-host routing exposes alternate app (Host: ${vh})`, status: 'warn', severity: 'medium',
          evidence: `Setting Host: ${vh} returned materially different content — an internal/staging vhost may be reachable.`,
          remediation: 'Restrict vhost routing; return a default deny for unknown Host headers.',
          request: { method: 'GET', url: base + '/', headers: { Host: vh }, payload: `Host: ${vh}`, status: r.status } });
        return;
      }
    }
  } catch (e) { log('debug', `vhost: ${e.message}`); }
}

async function run(ctx) {
  if (ctx.options.intensity !== 'aggressive') {
    ctx.log('debug', 'Infrastructure attacks skipped (requires Aggressive intensity).');
    return;
  }
  ctx.log('info', 'Infrastructure: actuator/debug endpoints, cloud metadata, subdomain takeover, VCS dump, backup archives, vhost bypass...');
  const steps = [
    ['debug endpoints', debugEndpoints], ['cloud metadata', cloudMetadata], ['subdomain takeover', subdomainTakeover],
    ['VCS dump', vcsDump], ['backup archives', backupArchives], ['vhost bypass', vhostBypass],
  ];
  for (const [name, fn] of steps) {
    ctx.log('debug', `→ ${name}`);
    try { await fn(ctx); } catch (e) { ctx.log('debug', `${name} error: ${e.message}`); }
  }
}

module.exports = { id: 'infraAttacks', category: 'Configuration Management', run };
