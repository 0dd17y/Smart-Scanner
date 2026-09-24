'use strict';

/**
 * secureTransmission.js — TLS/SSL posture (Secure Transmission).
 * Certificate validity, protocol versions, HTTPS redirect, HSTS.
 */

const { URL } = require('url');

const REF =
  'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html';

async function run(ctx) {
  const { http, target, log, finding } = ctx;
  const u = new URL(target);

  // --- HTTP -> HTTPS redirect check ---
  if (u.protocol === 'http:') {
    log('info', 'Target is HTTP; checking for an upgrade to HTTPS...');
    try {
      const res = await http.request(target, { timeout: 12000, followRedirects: true });
      const endsHttps = res.finalUrl.startsWith('https:');
      if (endsHttps) {
        log('ok', `HTTP redirects to HTTPS (${res.finalUrl})`);
        finding({
          category: 'Secure Transmission', title: 'HTTP to HTTPS redirect',
          status: 'pass', severity: 'info', evidence: `Redirect chain ended at ${res.finalUrl}`,
          remediation: 'No action required.', reference: REF,
        });
      } else {
        log('vuln', 'Site served over plaintext HTTP without redirect to HTTPS');
        finding({
          category: 'Secure Transmission', title: 'No HTTPS enforcement',
          status: 'fail', severity: 'high',
          evidence: `Final URL ${res.finalUrl} is not HTTPS.`,
          remediation: 'Redirect all HTTP traffic to HTTPS and enable HSTS.', reference: REF,
        });
      }
    } catch (e) {
      log('warn', `HTTPS redirect check failed: ${e.message}`);
    }
    log('info', 'Skipping certificate inspection (target is HTTP).');
    return;
  }

  // --- TLS certificate + protocol inspection (HTTPS) ---
  const host = u.hostname;
  const port = u.port ? Number(u.port) : 443;
  log('info', `Opening TLS connection to ${host}:${port} for certificate inspection...`);

  let info;
  try {
    info = await http.inspectTls(host, port);
  } catch (e) {
    log('warn', `TLS inspection failed: ${e.message}`);
    finding({
      category: 'Secure Transmission', title: 'TLS handshake',
      status: 'warn', severity: 'medium', evidence: e.message,
      remediation: 'Verify the TLS configuration and certificate chain.', reference: REF,
    });
    return;
  }

  const { cert, cipher, protocol, authorized, authError } = info;
  log('debug', `Negotiated ${protocol} with ${cipher && cipher.name}`);

  // Certificate validity window
  if (cert && cert.valid_to) {
    const notAfter = new Date(cert.valid_to);
    const daysLeft = Math.round((notAfter - Date.now()) / 86400000);
    const subject = (cert.subject && (cert.subject.CN || JSON.stringify(cert.subject))) || 'unknown';
    const issuer = (cert.issuer && (cert.issuer.CN || cert.issuer.O)) || 'unknown';
    log('info', `Cert CN=${subject}, issuer=${issuer}, expires in ${daysLeft} day(s)`);

    if (daysLeft < 0) {
      log('vuln', 'Certificate has EXPIRED');
      finding({
        category: 'Secure Transmission', title: 'Expired TLS certificate',
        status: 'fail', severity: 'high',
        evidence: `Expired on ${cert.valid_to} (${Math.abs(daysLeft)} days ago).`,
        remediation: 'Renew the certificate immediately.', reference: REF,
      });
    } else if (daysLeft < 21) {
      log('warn', `Certificate expires soon (${daysLeft} days)`);
      finding({
        category: 'Secure Transmission', title: 'TLS certificate expiring soon',
        status: 'warn', severity: 'low',
        evidence: `Valid until ${cert.valid_to} (${daysLeft} days).`,
        remediation: 'Schedule certificate renewal.', reference: REF,
      });
    } else {
      finding({
        category: 'Secure Transmission', title: 'TLS certificate validity',
        status: 'pass', severity: 'info',
        evidence: `Valid until ${cert.valid_to} (${daysLeft} days).`,
        remediation: 'No action required.', reference: REF,
      });
    }
  }

  // Trust / self-signed
  if (!authorized) {
    log('vuln', `Certificate not trusted: ${authError}`);
    finding({
      category: 'Secure Transmission', title: 'Untrusted / self-signed certificate',
      status: 'fail', severity: 'medium',
      evidence: authError || 'Certificate chain not authorized.',
      remediation: 'Use a certificate issued by a trusted CA for the correct hostname.',
      reference: REF,
    });
  }

  // Hostname / CN match
  if (cert && cert.subject && cert.subject.CN) {
    const cn = cert.subject.CN;
    const san = cert.subjectaltname || '';
    const matches =
      cn === host ||
      san.split(',').some((s) => {
        const val = s.split(':')[1] || '';
        if (val.startsWith('*.')) return host.endsWith(val.slice(1));
        return val === host;
      });
    if (!matches) {
      log('warn', `Certificate CN/SAN does not match host ${host}`);
      finding({
        category: 'Secure Transmission', title: 'Certificate hostname mismatch',
        status: 'warn', severity: 'medium',
        evidence: `CN=${cn}; SAN=${san}; host=${host}`,
        remediation: 'Issue a certificate covering the served hostname.', reference: REF,
      });
    }
  }

  // Weak legacy protocol support
  log('info', 'Probing for legacy TLS protocol support (TLSv1 / TLSv1.1)...');
  for (const [ver, label] of [['TLSv1', 'TLSv1.0'], ['TLSv1.1', 'TLSv1.1']]) {
    const supported = await http.probeTlsProtocol(host, port, ver);
    if (supported) {
      log('vuln', `${label} is supported (deprecated / weak)`);
      finding({
        category: 'Secure Transmission', title: `Weak protocol supported: ${label}`,
        status: 'fail', severity: 'medium',
        evidence: `Server completed a ${label} handshake.`,
        remediation: `Disable ${label}; require TLS 1.2+ (prefer 1.3).`, reference: REF,
      });
    } else {
      log('ok', `${label} not supported`);
    }
  }

  // HSTS presence on HTTPS
  try {
    const res = await http.request(target, { timeout: 12000 });
    const hsts = res.headers['strict-transport-security'];
    if (hsts) {
      log('ok', `HSTS present: ${hsts}`);
      finding({
        category: 'Secure Transmission', title: 'HSTS enabled',
        status: 'pass', severity: 'info', evidence: hsts,
        remediation: 'No action required.', reference: REF,
      });
    } else {
      log('vuln', 'HSTS header not set on HTTPS response');
      finding({
        category: 'Secure Transmission', title: 'HSTS not enabled',
        status: 'fail', severity: 'medium',
        evidence: 'No Strict-Transport-Security header on HTTPS response.',
        remediation: 'Add Strict-Transport-Security with a long max-age and includeSubDomains.',
        reference: REF,
      });
    }
  } catch (e) {
    log('debug', `HSTS re-check failed: ${e.message}`);
  }
}

module.exports = { id: 'secureTransmission', category: 'Secure Transmission', run };
