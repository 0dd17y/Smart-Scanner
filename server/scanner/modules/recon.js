'use strict';

/**
 * recon.js — technology fingerprinting + robots/sitemap discovery
 * (Information Gathering).
 */

const { URL } = require('url');

const REF = 'https://owasp.org/www-project-web-security-testing-guide/';

const TECH_SIGNS = [
  { name: 'Nginx', test: (h) => /nginx/i.test(h.server || '') },
  { name: 'Apache', test: (h) => /apache/i.test(h.server || '') },
  { name: 'IIS', test: (h) => /iis/i.test(h.server || '') },
  { name: 'Express', test: (h) => /express/i.test(h['x-powered-by'] || '') },
  { name: 'PHP', test: (h) => /php/i.test(h['x-powered-by'] || '') },
  { name: 'ASP.NET', test: (h) => !!h['x-aspnet-version'] || /asp\.net/i.test(h['x-powered-by'] || '') },
  { name: 'Cloudflare', test: (h) => /cloudflare/i.test(h.server || '') || !!h['cf-ray'] },
];

const BODY_SIGNS = [
  { name: 'WordPress', re: /wp-content|wp-includes/i },
  { name: 'Drupal', re: /Drupal\.settings|\/sites\/default\/files/i },
  { name: 'React', re: /data-reactroot|__NEXT_DATA__/i },
  { name: 'Angular', re: /ng-version|ng-app/i },
  { name: 'Vue', re: /data-v-[0-9a-f]{8}|__vue__/i },
];

async function run(ctx) {
  const { http, target, log, finding } = ctx;
  const u = new URL(target);

  let res = ctx.shared.baseResponse;
  if (!res) {
    try {
      res = await http.request(target, { timeout: 12000 });
      ctx.shared.baseResponse = res;
    } catch (e) {
      log('warn', `Recon fetch failed: ${e.message}`);
      return;
    }
  }

  log('info', `Fingerprinting ${u.host} (port ${u.port || (u.protocol === 'https:' ? 443 : 80)})...`);
  const found = new Set();
  for (const t of TECH_SIGNS) if (t.test(res.headers)) found.add(t.name);
  for (const b of BODY_SIGNS) if (b.re.test(res.body || '')) found.add(b.name);

  const list = [...found];
  if (list.length) {
    log('info', `Technologies detected: ${list.join(', ')}`);
  } else {
    log('debug', 'No definitive technology signatures matched.');
  }
  finding({
    category: 'Information Gathering', title: 'Technology fingerprint',
    status: 'info', severity: 'info',
    evidence: list.length ? list.join(', ') : 'No definitive signatures matched.',
    remediation: 'Minimize version disclosure where possible.', reference: REF,
  });

  // robots.txt + sitemap.xml
  for (const path of ['/robots.txt', '/sitemap.xml']) {
    const url = new URL(path, `${u.protocol}//${u.host}`).toString();
    log('info', `Checking ${path} ...`);
    try {
      const r = await http.request(url, { timeout: 10000 });
      if (r.status === 200 && r.body.trim()) {
        const snippet = r.body.split('\n').slice(0, 8).join('\n');
        log('warn', `${path} is accessible (${r.body.length} bytes)`);
        finding({
          category: 'Information Gathering', title: `${path} exposed`,
          status: 'info', severity: 'info',
          evidence: snippet,
          remediation:
            'Review that these files do not reveal sensitive or hidden paths.',
          reference: REF,
        });
        if (path === '/robots.txt') {
          const disallows = (r.body.match(/Disallow:\s*(\S+)/gi) || []).slice(0, 20);
          if (disallows.length) {
            log('info', `robots.txt Disallow entries: ${disallows.length}`);
            ctx.shared.robotsDisallow = disallows;
          }
        }
      } else {
        log('ok', `${path} not present (HTTP ${r.status})`);
      }
    } catch (e) {
      log('debug', `${path} check error: ${e.message}`);
    }
  }
}

module.exports = { id: 'recon', category: 'Information Gathering', run };
