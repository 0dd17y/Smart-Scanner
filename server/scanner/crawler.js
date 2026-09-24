'use strict';

/**
 * crawler.js — shallow, same-origin crawl to discover injectable surface:
 * links carrying query parameters and HTML forms (with their inputs).
 * Intentionally bounded (depth + page cap) so it never runs away.
 */

const { URL } = require('url');
const http = require('./httpClient');

function sameOrigin(a, b) {
  try {
    const ua = new URL(a);
    const ub = new URL(b);
    return ua.protocol === ub.protocol && ua.host === ub.host;
  } catch {
    return false;
  }
}

function extractLinks(html, baseUrl) {
  const links = new Set();
  const re = /(?:href|src|action)\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const raw = m[1];
    if (/^(javascript:|mailto:|tel:|#|data:)/i.test(raw)) continue;
    try {
      links.add(new URL(raw, baseUrl).toString());
    } catch {
      /* ignore malformed */
    }
  }
  return [...links];
}

// Very small HTML form parser (regex-based; good enough for surface discovery).
function extractForms(html, baseUrl) {
  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html)) !== null) {
    const attrs = fm[1];
    const inner = fm[2];
    const actionMatch = /action\s*=\s*["']([^"']*)["']/i.exec(attrs);
    const methodMatch = /method\s*=\s*["']([^"']*)["']/i.exec(attrs);
    let action = baseUrl;
    if (actionMatch && actionMatch[1]) {
      try {
        action = new URL(actionMatch[1], baseUrl).toString();
      } catch {
        action = baseUrl;
      }
    }
    const method = (methodMatch ? methodMatch[1] : 'GET').toUpperCase();

    const inputs = [];
    const inputRe = /<(input|textarea|select)\b([^>]*)>/gi;
    let im;
    while ((im = inputRe.exec(inner)) !== null) {
      const iattrs = im[2];
      const nameM = /name\s*=\s*["']([^"']*)["']/i.exec(iattrs);
      const typeM = /type\s*=\s*["']([^"']*)["']/i.exec(iattrs);
      const valM = /value\s*=\s*["']([^"']*)["']/i.exec(iattrs);
      if (nameM && nameM[1]) {
        inputs.push({
          name: nameM[1],
          type: (typeM ? typeM[1] : 'text').toLowerCase(),
          value: valM ? valM[1] : '',
        });
      }
    }
    forms.push({ action, method, inputs });
  }
  return forms;
}

function paramsOf(urlStr) {
  try {
    const u = new URL(urlStr);
    return [...u.searchParams.keys()];
  } catch {
    return [];
  }
}

/**
 * crawl(target, { maxPages, maxDepth, log })
 * Returns { pages, paramUrls, forms }.
 */
async function crawl(target, opts = {}) {
  const maxPages = opts.maxPages ?? 25;
  const maxDepth = opts.maxDepth ?? 2;
  const log = opts.log || (() => {});

  const visited = new Set();
  const queue = [{ url: target, depth: 0 }];
  const pages = [];
  const paramUrls = new Map(); // url -> params[]
  const forms = [];

  while (queue.length && pages.length < maxPages) {
    const { url, depth } = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);

    let res;
    try {
      res = await http.request(url, { timeout: 12000 });
    } catch (e) {
      log('debug', `crawl: ${url} -> ${e.message}`);
      continue;
    }

    const ctype = String(res.headers['content-type'] || '');
    pages.push({ url: res.finalUrl, status: res.status, contentType: ctype });
    log('debug', `crawled ${res.finalUrl} [${res.status}] ${ctype.split(';')[0]}`);

    if (!ctype.includes('html')) continue;

    // record params on this URL
    const p = paramsOf(res.finalUrl);
    if (p.length) paramUrls.set(res.finalUrl, p);

    // forms
    for (const f of extractForms(res.body, res.finalUrl)) {
      forms.push(f);
    }

    if (depth < maxDepth) {
      for (const link of extractLinks(res.body, res.finalUrl)) {
        if (!sameOrigin(link, target)) continue;
        if (visited.has(link)) continue;
        const lp = paramsOf(link);
        if (lp.length) paramUrls.set(link, lp);
        queue.push({ url: link, depth: depth + 1 });
      }
    }
  }

  return {
    pages,
    paramUrls: [...paramUrls.entries()].map(([url, params]) => ({ url, params })),
    forms,
  };
}

module.exports = { crawl, sameOrigin, extractLinks, extractForms, paramsOf };
