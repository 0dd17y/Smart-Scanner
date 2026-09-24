/* siteinfo.js — Site/Portal Information tab: fetches /api/siteinfo and renders a
 * rich, animated profile of the target. */
(function (global) {
  'use strict';
  const $ = (s) => document.querySelector(s);
  let wired = false;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])
    );
  }
  const val = (v) => (v == null || v === '' || (Array.isArray(v) && !v.length))
    ? '<span class="si-muted">—</span>' : esc(Array.isArray(v) ? v.join(', ') : v);

  function kv(label, v) {
    return `<div class="si-row"><span class="si-k">${esc(label)}</span><span class="si-v">${
      typeof v === 'string' && v.startsWith('<') ? v : val(v)
    }</span></div>`;
  }
  function chip(t, cls) { return `<span class="si-chip ${cls || ''}">${esc(t)}</span>`; }
  function badge(label, state) {
    // state: good | bad | warn | unknown
    const map = { good: '✓', bad: '✗', warn: '!', unknown: '?' };
    return `<span class="si-badge ${state}">${map[state] || '?'} ${esc(label)}</span>`;
  }
  function card(title, inner, icon) {
    return `<div class="si-card panel"><div class="si-card-h">${icon ? icon + ' ' : ''}${esc(title)}</div>${inner}</div>`;
  }

  function render(d) {
    const results = $('#siResults');
    if (!d.ok) {
      results.innerHTML = `<div class="si-card panel"><div class="si-card-h">Error</div><div class="si-row"><span class="si-v" style="color:var(--red)">${esc(d.error || 'Failed')}</span></div></div>`;
      return;
    }
    const o = d.overview, t = d.tls, dnsi = d.dns, tech = d.technology, p = d.posture, s = d.structure;
    const cards = [];

    // Overview
    cards.push(card('Overview', [
      kv('Final URL', o.finalUrl),
      kv('Status', o.status),
      kv('HTTP version', o.httpVersion),
      kv('Response time', o.responseTimeMs != null ? o.responseTimeMs + ' ms' : null),
      kv('Content-Type', o.contentType),
      kv('Page size', o.pageBytes != null ? o.pageBytes.toLocaleString() + ' bytes' : null),
      kv('Title', o.title),
      kv('Description', o.description),
      kv('Charset', o.charset),
      kv('Language', o.lang),
      o.redirectChain && o.redirectChain.length > 1
        ? kv('Redirect chain', o.redirectChain.join('  →  ')) : '',
    ].join(''), '🛰'));

    // Security posture
    const postureBadges = [
      badge('HTTPS', p.https ? 'good' : 'bad'),
      badge('HSTS', p.hsts ? 'good' : 'bad'),
      badge('CSP', p.csp ? 'good' : 'bad'),
      badge('Clickjacking protection', p.clickjackingProtb ? 'good' : 'bad'),
      badge('Cookies Secure', p.cookiesSecure == null ? 'unknown' : p.cookiesSecure ? 'good' : 'bad'),
      badge('Weak TLS', p.weakTlsSupported == null ? 'unknown' : p.weakTlsSupported ? 'bad' : 'good'),
    ];
    if (p.cdnWaf) postureBadges.push(badge('CDN/WAF: ' + p.cdnWaf.join(', '), 'good'));
    cards.push(card('Security posture', `<div class="si-badges">${postureBadges.join('')}</div>`, '🛡'));

    // TLS / Certificate
    if (t && t.available) {
      const matrix = t.protocolMatrix || {};
      const matrixHtml = '<div class="si-matrix">' + Object.entries(matrix).map(([k, v]) =>
        `<span class="si-proto ${v ? (/(1\.0|1\.1)/.test(k) ? 'weak' : 'on') : 'off'}">${esc(k)} ${v ? '✓' : '✗'}</span>`
      ).join('') + '</div>';
      cards.push(card('SSL / TLS certificate', [
        kv('Protocol', t.protocol),
        kv('Cipher', t.cipher),
        kv('Trusted', t.trusted ? 'Yes' : 'No — ' + (t.trustError || 'untrusted')),
        kv('Subject CN', t.subjectCN),
        kv('Issuer', t.issuer),
        kv('Serial', t.serialNumber),
        kv('Valid from', t.validFrom),
        kv('Valid to', t.validTo + (t.daysRemaining != null ? ` (${t.daysRemaining} days left)` : '')),
        kv('Key', [t.keyType, t.keyBits ? t.keyBits + '-bit' : ''].filter(Boolean).join(' ')),
        kv('SAN', t.san),
        kv('Self-signed', t.selfSigned == null ? null : (t.selfSigned ? 'Yes' : 'No')),
        kv('SHA-256', t.fingerprint256),
        kv('Supported protocols', matrixHtml),
      ].join(''), '🔒'));
    } else {
      cards.push(card('SSL / TLS certificate',
        `<div class="si-row"><span class="si-v si-muted">${esc(t && (t.reason || t.error) || 'Not available (target is not HTTPS)')}</span></div>`, '🔒'));
    }

    // DNS & Network
    cards.push(card('DNS & network', [
      kv('A (IPv4)', dnsi.a),
      kv('AAAA (IPv6)', dnsi.aaaa),
      kv('CNAME', dnsi.cname),
      kv('MX', dnsi.mx),
      kv('NS', dnsi.ns),
      kv('TXT', dnsi.txt),
      kv('Reverse PTR', dnsi.reversePtr),
    ].join(''), '🌐'));

    // Technology
    cards.push(card('Technology', [
      tech.stack.length ? `<div class="si-row"><span class="si-k">Stack</span><span class="si-v">${tech.stack.map((x) => chip(x)).join('')}</span></div>` : kv('Stack', null),
      kv('Server', tech.server),
      kv('X-Powered-By', tech.poweredBy),
      kv('Generator', tech.generator),
      tech.cdnWaf.length ? `<div class="si-row"><span class="si-k">CDN / WAF</span><span class="si-v">${tech.cdnWaf.map((x) => chip(x, 'cdn')).join('')}</span></div>` : kv('CDN / WAF', null),
    ].join(''), '🧩'));

    // Page structure
    cards.push(card('Page structure', [
      kv('Scripts', s.scripts), kv('Stylesheets', s.stylesheets), kv('Images', s.images),
      kv('Iframes', s.iframes), kv('Forms', s.forms),
      kv('Links', `${s.links} (${s.internalLinks} internal / ${s.externalLinks} external)`),
    ].join(''), '📄'));

    // Cookies
    const cookieHtml = d.cookies.length
      ? d.cookies.map((c) =>
          `<div class="si-row"><span class="si-k">${esc(c.name)}</span><span class="si-v">${
            [c.secure ? badge('Secure', 'good') : badge('Secure', 'bad'),
             c.httpOnly ? badge('HttpOnly', 'good') : badge('HttpOnly', 'bad'),
             badge('SameSite=' + (c.sameSite || 'none'), c.sameSite ? 'good' : 'warn')].join(' ')
          }</span></div>`).join('')
      : `<div class="si-row"><span class="si-v si-muted">No cookies set on initial response</span></div>`;
    cards.push(card('Cookies', cookieHtml, '🍪'));

    // Well-known files
    cards.push(card('Well-known files', [
      kv('robots.txt', d.files.robots.present ? `Present (${d.files.robots.disallowCount} Disallow entries)` : 'Not found'),
      kv('sitemap.xml', d.files.sitemap.present ? 'Present' : 'Not found'),
      kv('security.txt', d.files.securityTxt.present ? 'Present' : 'Not found'),
    ].join(''), '📁'));

    // HTTP headers (full)
    const headerRows = Object.entries(d.headers || {}).map(([k, v]) =>
      `<tr><td>${esc(k)}</td><td>${esc(Array.isArray(v) ? v.join(' | ') : v)}</td></tr>`).join('');
    cards.push(card('HTTP response headers',
      `<table class="si-headers"><tbody>${headerRows}</tbody></table>`, '📨'));

    results.innerHTML = cards.join('');
    // staggered reveal
    Array.from(results.children).forEach((el, i) => {
      el.style.animationDelay = (i * 60) + 'ms';
      el.classList.add('si-reveal');
    });
  }

  async function gather() {
    const url = $('#siUrl').value.trim();
    if (!url) return;
    $('#siLoader').classList.add('show');
    $('#siResults').innerHTML = '';
    $('#siGather').disabled = true;
    try {
      const res = await fetch('/api/siteinfo?url=' + encodeURIComponent(url));
      const data = await res.json();
      render(data);
    } catch (e) {
      render({ ok: false, error: e.message });
    } finally {
      $('#siLoader').classList.remove('show');
      $('#siGather').disabled = false;
    }
  }

  function init() {
    if (wired) return;
    wired = true;
    $('#siGather').addEventListener('click', gather);
    $('#siUrl').addEventListener('keydown', (e) => { if (e.key === 'Enter') gather(); });
    // prefill from the scanner URL if the user already typed one
    const scanUrl = document.getElementById('url');
    if (scanUrl && scanUrl.value && !$('#siUrl').value) $('#siUrl').value = scanUrl.value;
  }

  global.SmartSiteInfo = { init };
})(window);
