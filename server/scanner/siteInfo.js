'use strict';

/**
 * siteInfo.js — passive reconnaissance / portal profile.
 * Gathers a rich, read-only summary of a target: overview, DNS, TLS/cert, headers,
 * technology, cookies, page structure, well-known files, and a posture roll-up.
 *
 * Everything here is passive: plain GETs plus one TLS handshake and DNS lookups.
 */

const dns = require('dns').promises;
const { URL } = require('url');
const http = require('./httpClient');
const crawler = require('./crawler');
const { normalizeTarget } = require('./orchestrator');

// ---- helpers ---------------------------------------------------------------
const SEC_HEADERS = [
  ['content-security-policy', 'Content-Security-Policy'],
  ['strict-transport-security', 'Strict-Transport-Security (HSTS)'],
  ['x-frame-options', 'X-Frame-Options'],
  ['x-content-type-options', 'X-Content-Type-Options'],
  ['referrer-policy', 'Referrer-Policy'],
  ['permissions-policy', 'Permissions-Policy'],
];

const TECH_HEADER_SIGNS = [
  { name: 'Nginx', test: (h) => /nginx/i.test(h.server || '') },
  { name: 'Apache', test: (h) => /apache/i.test(h.server || '') },
  { name: 'Microsoft IIS', test: (h) => /iis|microsoft-httpapi/i.test(h.server || '') },
  { name: 'LiteSpeed', test: (h) => /litespeed/i.test(h.server || '') },
  { name: 'Express', test: (h) => /express/i.test(h['x-powered-by'] || '') },
  { name: 'PHP', test: (h) => /php/i.test(h['x-powered-by'] || '') || /php/i.test(h['set-cookie'] || '') },
  { name: 'ASP.NET', test: (h) => !!h['x-aspnet-version'] || /asp\.net/i.test(h['x-powered-by'] || '') },
  { name: 'Node.js', test: (h) => /node/i.test(h['x-powered-by'] || '') },
];

const TECH_BODY_SIGNS = [
  { name: 'WordPress', re: /wp-content|wp-includes|<meta name="generator" content="WordPress/i },
  { name: 'Drupal', re: /Drupal\.settings|\/sites\/default\/files|X-Generator: Drupal/i },
  { name: 'Joomla', re: /\/media\/jui\/|Joomla!/i },
  { name: 'React', re: /data-reactroot|__NEXT_DATA__|_next\/static/i },
  { name: 'Next.js', re: /__NEXT_DATA__|_next\/static/i },
  { name: 'Angular', re: /ng-version|ng-app|angular/i },
  { name: 'Vue.js', re: /data-v-[0-9a-f]{8}|__vue__|vue(\.min)?\.js/i },
  { name: 'jQuery', re: /jquery(\.min)?\.js/i },
  { name: 'Bootstrap', re: /bootstrap(\.min)?\.(css|js)/i },
  { name: 'Google Analytics', re: /gtag\(|google-analytics\.com|googletagmanager\.com/i },
];

const CDN_WAF_SIGNS = [
  { name: 'Cloudflare', test: (h) => !!h['cf-ray'] || /cloudflare/i.test(h.server || '') },
  { name: 'Akamai', test: (h) => /akamai/i.test((h.server || '') + (h['x-akamai-transformed'] || '')) || 'x-akamai-transformed' in h },
  { name: 'Fastly', test: (h) => /fastly/i.test((h.via || '') + (h['x-served-by'] || '')) || /fastly/i.test(h['x-cache'] || '') },
  { name: 'Amazon CloudFront', test: (h) => /cloudfront/i.test((h.via || '') + (h['x-amz-cf-id'] ? 'cf' : '')) || 'x-amz-cf-id' in h },
  { name: 'Sucuri', test: (h) => /sucuri/i.test((h.server || '') + (h['x-sucuri-id'] || '')) },
  { name: 'Imperva/Incapsula', test: (h) => 'x-iinfo' in h || /incap_ses|visid_incap/i.test(h['set-cookie'] || '') },
  { name: 'Varnish', test: (h) => /varnish/i.test((h.via || '') + (h['x-varnish'] ? 'v' : '')) || 'x-varnish' in h },
];

function firstMatch(re, text) {
  const m = re.exec(text || '');
  return m ? (m[1] || m[0]) : null;
}

function parseCookieFlags(raw) {
  const parts = raw.split(';').map((p) => p.trim());
  const name = (parts[0] || '').split('=')[0];
  const lower = parts.slice(1).map((p) => p.toLowerCase());
  return {
    name,
    secure: lower.some((p) => p === 'secure'),
    httpOnly: lower.some((p) => p === 'httponly'),
    sameSite: (parts.find((p) => /^samesite=/i.test(p)) || '').split('=')[1] || null,
  };
}

async function safe(promise, fallback) {
  try {
    return await promise;
  } catch {
    return fallback;
  }
}

// ---- section gatherers -----------------------------------------------------
async function getDns(hostname) {
  const out = {
    a: await safe(dns.resolve4(hostname), []),
    aaaa: await safe(dns.resolve6(hostname), []),
    cname: await safe(dns.resolveCname(hostname), []),
    mx: (await safe(dns.resolveMx(hostname), [])).map((m) => `${m.exchange} (pri ${m.priority})`),
    ns: await safe(dns.resolveNs(hostname), []),
    txt: (await safe(dns.resolveTxt(hostname), [])).map((t) => t.join('')),
  };
  const primaryIp = out.a[0];
  out.reversePtr = primaryIp ? await safe(dns.reverse(primaryIp), []) : [];
  return out;
}

async function getTls(hostname, port) {
  let info;
  try {
    info = await http.inspectTls(hostname, port);
  } catch (e) {
    return { available: false, error: e.message };
  }
  const { cert, cipher, protocol, authorized, authError } = info;
  const daysRemaining =
    cert && cert.valid_to
      ? Math.round((new Date(cert.valid_to) - Date.now()) / 86400000)
      : null;

  // key type inference
  let keyType = 'unknown';
  let keyBits = cert && cert.bits ? cert.bits : null;
  if (cert && cert.asn1Curve) keyType = `EC (${cert.asn1Curve})`;
  else if (cert && cert.bits) keyType = 'RSA';

  // supported protocol matrix
  const matrix = {};
  for (const [ver, label] of [
    ['TLSv1', 'TLS 1.0'],
    ['TLSv1.1', 'TLS 1.1'],
    ['TLSv1.2', 'TLS 1.2'],
    ['TLSv1.3', 'TLS 1.3'],
  ]) {
    matrix[label] = await http.probeTlsProtocol(hostname, port, ver);
  }

  return {
    available: true,
    protocol,
    cipher: cipher ? `${cipher.name} (${cipher.version})` : null,
    trusted: authorized,
    trustError: authError,
    subjectCN: cert && cert.subject ? cert.subject.CN : null,
    san: cert && cert.subjectaltname ? cert.subjectaltname.split(',').map((s) => s.trim()) : [],
    issuer: cert && cert.issuer ? cert.issuer.CN || cert.issuer.O : null,
    serialNumber: cert ? cert.serialNumber : null,
    validFrom: cert ? cert.valid_from : null,
    validTo: cert ? cert.valid_to : null,
    daysRemaining,
    keyType,
    keyBits,
    fingerprint256: cert ? cert.fingerprint256 : null,
    selfSigned:
      cert && cert.subject && cert.issuer
        ? JSON.stringify(cert.subject) === JSON.stringify(cert.issuer)
        : null,
    protocolMatrix: matrix,
  };
}

function getTechnology(headers, body) {
  const tech = new Set();
  for (const t of TECH_HEADER_SIGNS) if (t.test(headers)) tech.add(t.name);
  for (const b of TECH_BODY_SIGNS) if (b.re.test(body || '')) tech.add(b.name);
  const generator = firstMatch(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i, body);
  if (generator) tech.add(generator);
  const cdnWaf = CDN_WAF_SIGNS.filter((c) => c.test(headers)).map((c) => c.name);
  return {
    stack: [...tech],
    server: headers.server || null,
    poweredBy: headers['x-powered-by'] || null,
    generator: generator || null,
    cdnWaf,
  };
}

function pageStructure(body, baseUrl) {
  const count = (re) => (body.match(re) || []).length;
  const links = crawler.extractLinks(body, baseUrl);
  let internal = 0;
  let external = 0;
  for (const l of links) {
    if (crawler.sameOrigin(l, baseUrl)) internal++;
    else external++;
  }
  return {
    scripts: count(/<script\b/gi),
    stylesheets: count(/<link[^>]+rel=["']stylesheet["']/gi),
    images: count(/<img\b/gi),
    iframes: count(/<iframe\b/gi),
    forms: crawler.extractForms(body, baseUrl).length,
    links: links.length,
    internalLinks: internal,
    externalLinks: external,
  };
}

async function checkFile(base, path) {
  try {
    const r = await http.request(base + path, { timeout: 9000 });
    return { path, status: r.status, present: r.status === 200 && (r.body || '').length > 0, body: r.body || '' };
  } catch {
    return { path, status: 0, present: false, body: '' };
  }
}

// ---- main ------------------------------------------------------------------
async function gather(rawTarget) {
  const target = normalizeTarget(rawTarget); // throws on invalid
  const u = new URL(target);
  const isHttps = u.protocol === 'https:';
  const port = u.port ? Number(u.port) : isHttps ? 443 : 80;
  const base = `${u.protocol}//${u.host}`;

  http.resetCounters();
  http.setLimits({ concurrency: 8, totalCap: 200 });

  // main fetch (follow redirects to profile the landing page)
  let res;
  try {
    res = await http.request(target, { timeout: 12000, followRedirects: true });
  } catch (e) {
    return { ok: false, target, error: `Could not fetch target: ${e.message}` };
  }
  const body = res.body || '';
  const headers = res.headers || {};

  // overview
  const title = firstMatch(/<title[^>]*>([\s\S]*?)<\/title>/i, body);
  const description = firstMatch(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i, body);
  const charset =
    firstMatch(/<meta[^>]+charset=["']?([\w-]+)/i, body) ||
    firstMatch(/charset=([\w-]+)/i, headers['content-type'] || '');
  const lang = firstMatch(/<html[^>]+lang=["']([^"']+)["']/i, body);
  let favicon = firstMatch(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']/i, body);
  if (favicon) {
    try { favicon = new URL(favicon, res.finalUrl).toString(); } catch { /* keep raw */ }
  } else {
    favicon = base + '/favicon.ico';
  }

  const overview = {
    inputUrl: target,
    finalUrl: res.finalUrl,
    redirectChain: (res.redirectChain || []).map((c) => `${c.status} ${c.url}`),
    status: `${res.status} ${res.statusMessage || ''}`.trim(),
    httpVersion: res.httpVersion ? `HTTP/${res.httpVersion}` : null,
    responseTimeMs: res.elapsedMs,
    contentType: headers['content-type'] || null,
    pageBytes: Buffer.byteLength(body),
    title: title ? title.trim().replace(/\s+/g, ' ') : null,
    description: description || null,
    charset: charset || null,
    lang: lang || null,
    favicon,
  };

  // security headers summary
  const securityHeaders = SEC_HEADERS.map(([key, label]) => ({
    label,
    present: !!headers[key],
    value: headers[key] || null,
  }));

  // cookies
  const cookies = (res.setCookies || []).map(parseCookieFlags);

  // well-known files
  const robots = await checkFile(base, '/robots.txt');
  const sitemap = await checkFile(base, '/sitemap.xml');
  const securityTxt = await checkFile(base, '/.well-known/security.txt');
  const disallowCount = robots.present
    ? (robots.body.match(/Disallow:/gi) || []).length
    : 0;
  const files = {
    robots: { present: robots.present, disallowCount },
    sitemap: { present: sitemap.present },
    securityTxt: { present: securityTxt.present },
  };

  // dns + tls (in parallel where possible)
  const [dnsInfo, tlsInfo] = await Promise.all([
    getDns(u.hostname),
    isHttps ? getTls(u.hostname, port) : Promise.resolve({ available: false, reason: 'Target is not HTTPS' }),
  ]);

  const technology = getTechnology(headers, body);
  const structure = pageStructure(body, res.finalUrl);

  // posture roll-up
  let httpsRedirect = null;
  if (!isHttps) {
    httpsRedirect = res.finalUrl.startsWith('https:');
  }
  const posture = {
    https: isHttps || (httpsRedirect === true),
    hsts: !!headers['strict-transport-security'],
    csp: !!headers['content-security-policy'],
    clickjackingProtb:
      !!headers['x-frame-options'] || /frame-ancestors/i.test(headers['content-security-policy'] || ''),
    cookiesSecure: cookies.length ? cookies.every((c) => c.secure) : null,
    weakTlsSupported:
      tlsInfo.available && tlsInfo.protocolMatrix
        ? !!(tlsInfo.protocolMatrix['TLS 1.0'] || tlsInfo.protocolMatrix['TLS 1.1'])
        : null,
    cdnWaf: technology.cdnWaf.length ? technology.cdnWaf : null,
  };

  return {
    ok: true,
    target,
    gatheredAt: new Date().toISOString(),
    overview,
    dns: dnsInfo,
    tls: tlsInfo,
    headers: headers,
    securityHeaders,
    technology,
    cookies,
    structure,
    files,
    posture,
  };
}

module.exports = { gather };
