'use strict';

/**
 * httpClient.js
 * Low-level HTTP(S)/TLS client built on Node built-ins so we get full control over
 * raw headers, the redirect chain, Set-Cookie lists, and the peer TLS certificate.
 * Global concurrency + total-request caps keep us from accidentally stressing a target.
 */

const http = require('http');
const https = require('https');
const tls = require('tls');
const { URL } = require('url');

const DEFAULT_UA =
  'SmartScan/1.0 (+authorized security testing; contact=owner)';

// ---- Global throttle -------------------------------------------------------
let inFlight = 0;
let maxConcurrency = 12;
let totalRequests = 0;
let maxTotalRequests = 20000; // hard safety ceiling per process run
const waiters = [];

function setLimits({ concurrency, totalCap } = {}) {
  if (concurrency) maxConcurrency = concurrency;
  if (totalCap) maxTotalRequests = totalCap;
}

function acquire() {
  return new Promise((resolve, reject) => {
    if (totalRequests >= maxTotalRequests) {
      return reject(new Error('Global request cap reached (safety ceiling)'));
    }
    if (inFlight < maxConcurrency) {
      inFlight++;
      totalRequests++;
      resolve();
    } else {
      waiters.push({ resolve, reject });
    }
  });
}

function release() {
  inFlight--;
  const next = waiters.shift();
  if (next) {
    if (totalRequests >= maxTotalRequests) {
      return next.reject(new Error('Global request cap reached (safety ceiling)'));
    }
    inFlight++;
    totalRequests++;
    next.resolve();
  }
}

function resetCounters() {
  totalRequests = 0;
}

// ---- Single request (no auto redirect) ------------------------------------
function rawRequest(target, options = {}) {
  const {
    method = 'GET',
    headers = {},
    body = null,
    timeout = 12000,
    rejectUnauthorized = false, // we WANT to inspect bad certs, not fail on them
    maxBodyBytes = 2_000_000,
  } = options;

  return new Promise((resolve, reject) => {
    let urlObj;
    try {
      urlObj = new URL(target);
    } catch (e) {
      return reject(new Error(`Invalid URL: ${target}`));
    }

    const isHttps = urlObj.protocol === 'https:';
    const lib = isHttps ? https : http;

    const reqHeaders = {
      'User-Agent': DEFAULT_UA,
      Accept: '*/*',
      Connection: 'close',
      ...headers,
    };
    if (body != null && !('Content-Length' in reqHeaders)) {
      reqHeaders['Content-Length'] = Buffer.byteLength(body);
    }

    const started = Date.now();
    const req = lib.request(
      {
        protocol: urlObj.protocol,
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method,
        headers: reqHeaders,
        rejectUnauthorized,
        servername: urlObj.hostname,
      },
      (res) => {
        const chunks = [];
        let received = 0;
        let truncated = false;
        res.on('data', (c) => {
          received += c.length;
          if (received <= maxBodyBytes) {
            chunks.push(c);
          } else if (!truncated) {
            truncated = true;
            res.destroy();
          }
        });
        res.on('end', () => finish());
        res.on('close', () => finish());

        let done = false;
        function finish() {
          if (done) return;
          done = true;
          const elapsed = Date.now() - started;
          const bodyStr = Buffer.concat(chunks).toString('utf8');
          // Raw Set-Cookie list (undici/http keeps them separate here)
          const setCookies =
            typeof res.headers['set-cookie'] !== 'undefined'
              ? [].concat(res.headers['set-cookie'])
              : [];
          resolve({
            url: target,
            finalUrl: target,
            status: res.statusCode,
            statusMessage: res.statusMessage,
            httpVersion: res.httpVersion,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            setCookies,
            body: bodyStr,
            truncated,
            elapsedMs: elapsed,
            location: res.headers.location || null,
          });
        }
      }
    );

    req.on('error', (err) => reject(err));
    req.setTimeout(timeout, () => {
      req.destroy(new Error(`Request timed out after ${timeout}ms`));
    });

    if (body != null) req.write(body);
    req.end();
  });
}

// ---- Throttled request, optional redirect following ------------------------
async function request(target, options = {}) {
  const followRedirects = options.followRedirects !== false;
  const maxRedirects = options.maxRedirects ?? 6;

  await acquire();
  try {
    let current = target;
    const chain = [];
    let last = await rawRequest(current, options);
    chain.push({ url: current, status: last.status, location: last.location });

    let redirects = 0;
    while (
      followRedirects &&
      last.status >= 300 &&
      last.status < 400 &&
      last.location &&
      redirects < maxRedirects
    ) {
      redirects++;
      const nextUrl = new URL(last.location, current).toString();
      current = nextUrl;
      // release + re-acquire so redirects respect the throttle too
      release();
      await acquire();
      last = await rawRequest(current, options);
      chain.push({ url: current, status: last.status, location: last.location });
    }
    last.finalUrl = current;
    last.redirectChain = chain;
    return last;
  } finally {
    release();
  }
}

// ---- TLS certificate + protocol inspection --------------------------------
function inspectTls(hostname, port = 443, timeout = 12000) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        const authError = socket.authorizationError
          ? String(socket.authorizationError)
          : null;
        socket.end();
        resolve({ cert, cipher, protocol, authorized, authError });
      }
    );
    socket.on('error', (err) => reject(err));
    socket.setTimeout(timeout, () => {
      socket.destroy();
      reject(new Error('TLS connection timed out'));
    });
  });
}

// Attempt a handshake forcing a specific protocol; resolves true if supported.
function probeTlsProtocol(hostname, port, version, timeout = 8000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };
    let socket;
    try {
      socket = tls.connect({
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        minVersion: version,
        maxVersion: version,
        timeout,
      });
    } catch (e) {
      return done(false);
    }
    socket.on('secureConnect', () => {
      socket.destroy();
      done(true);
    });
    socket.on('error', () => {
      done(false);
    });
    socket.setTimeout(timeout, () => {
      socket.destroy();
      done(false);
    });
  });
}

module.exports = {
  request,
  rawRequest,
  inspectTls,
  probeTlsProtocol,
  setLimits,
  resetCounters,
  DEFAULT_UA,
};
