'use strict';

/**
 * headers.js — security response header analysis (Configuration Management).
 */

const REF =
  'https://owasp.org/www-project-secure-headers/';

async function run(ctx) {
  const { http, target, log, finding } = ctx;
  log('info', `Requesting ${target} to inspect security headers...`);

  let res;
  try {
    res = await http.request(target, { timeout: 12000 });
  } catch (e) {
    log('warn', `Could not fetch target for header analysis: ${e.message}`);
    finding({
      category: 'Configuration Management',
      title: 'Security headers',
      status: 'info',
      severity: 'info',
      evidence: e.message,
      remediation: 'Target unreachable; retry when the host is available.',
      reference: REF,
    });
    return;
  }

  ctx.shared.baseResponse = res;
  const h = res.headers;
  log('debug', `HTTP ${res.status} — ${Object.keys(h).length} response headers received`);

  const checks = [
    {
      title: 'Content-Security-Policy',
      present: !!h['content-security-policy'],
      severity: 'medium',
      remediation:
        'Define a restrictive Content-Security-Policy to mitigate XSS and data injection.',
    },
    {
      title: 'X-Frame-Options / frame-ancestors (clickjacking)',
      present:
        !!h['x-frame-options'] ||
        /frame-ancestors/i.test(h['content-security-policy'] || ''),
      severity: 'medium',
      remediation:
        'Set X-Frame-Options: DENY (or SAMEORIGIN) or a CSP frame-ancestors directive.',
    },
    {
      title: 'Strict-Transport-Security (HSTS)',
      present: !!h['strict-transport-security'],
      severity: target.startsWith('https') ? 'medium' : 'info',
      remediation:
        'Send Strict-Transport-Security with a long max-age and includeSubDomains over HTTPS.',
    },
    {
      title: 'X-Content-Type-Options',
      present: /nosniff/i.test(h['x-content-type-options'] || ''),
      severity: 'low',
      remediation: 'Set X-Content-Type-Options: nosniff to stop MIME sniffing.',
    },
    {
      title: 'Referrer-Policy',
      present: !!h['referrer-policy'],
      severity: 'low',
      remediation:
        'Set Referrer-Policy (e.g. strict-origin-when-cross-origin) to limit referrer leakage.',
    },
    {
      title: 'Permissions-Policy',
      present: !!h['permissions-policy'] || !!h['feature-policy'],
      severity: 'low',
      remediation:
        'Set Permissions-Policy to restrict powerful browser features (camera, geolocation, ...).',
    },
  ];

  for (const c of checks) {
    if (c.present) {
      log('ok', `${c.title}: present`);
      finding({
        category: 'Configuration Management',
        title: c.title,
        status: 'pass',
        severity: 'info',
        evidence: 'Header present',
        remediation: 'No action required.',
        reference: REF,
      });
    } else {
      log('vuln', `${c.title}: MISSING`);
      finding({
        category: 'Configuration Management',
        title: `Missing ${c.title}`,
        status: 'fail',
        severity: c.severity,
        evidence: `Response from ${res.finalUrl} did not include this header.`,
        remediation: c.remediation,
        reference: REF,
      });
    }
  }

  // Information disclosure via banner headers
  const banners = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
  const leaked = banners.filter((b) => h[b]).map((b) => `${b}: ${h[b]}`);
  if (leaked.length) {
    log('warn', `Technology/version banners exposed: ${leaked.join(', ')}`);
    finding({
      category: 'Information Gathering',
      title: 'Technology/version banner disclosure',
      status: 'warn',
      severity: 'low',
      evidence: leaked.join('\n'),
      remediation:
        'Suppress or genericize Server / X-Powered-By / version headers to reduce fingerprinting.',
      reference: REF,
    });
  } else {
    log('ok', 'No obvious technology banner headers exposed');
  }
}

module.exports = { id: 'headers', category: 'Configuration Management', run };
