'use strict';

/**
 * index.js — Smart Scan server.
 * Serves the animated UI and exposes:
 *   GET  /api/checklist          -> manual checklist data
 *   GET  /api/scan/stream        -> SSE stream of a live scan
 *   POST /api/report             -> standalone HTML report from findings JSON
 */

const path = require('path');
const express = require('express');
const { runScan } = require('./scanner/orchestrator');
const checklist = require('./scanner/checklist');
const siteInfo = require('./scanner/siteInfo');
const httpClient = require('./scanner/httpClient');
const { buildReport } = require('./report');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '4mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/checklist', (req, res) => {
  res.json({ groups: checklist.normalized(), owasp: checklist.OWASP });
});

app.get('/api/siteinfo', async (req, res) => {
  const target = req.query.url;
  if (!target) {
    res.status(400).json({ ok: false, error: 'Missing url parameter' });
    return;
  }
  try {
    const data = await siteInfo.gather(target);
    res.json(data);
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.get('/api/scan/stream', async (req, res) => {
  const target = req.query.url;
  if (!target) {
    res.status(400).json({ error: 'Missing url parameter' });
    return;
  }

  const options = {
    intensity: ['passive', 'active', 'aggressive'].includes(req.query.intensity)
      ? req.query.intensity
      : 'active',
    maxBruteAttempts: clampInt(req.query.maxBrute, 25, 1, 200),
    maxFuzz: clampInt(req.query.maxFuzz, 120, 1, 1000),
    dosRequests: clampInt(req.query.dosRequests, 30, 5, 200),
    // Advanced-check caps (Increment 3)
    maxIdor: clampInt(req.query.maxIdor, 15, 1, 100),
    maxJwtSecrets: clampInt(req.query.maxJwtSecrets, 250, 1, 2000),
    maxSpray: clampInt(req.query.maxSpray, 20, 1, 100),
    maxBodyKb: clampInt(req.query.maxBodyKb, 1024, 64, 5120),
  };

  // SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n');

  let closed = false;
  req.on('close', () => {
    closed = true;
  });

  const emit = (type, data) => {
    if (closed) return;
    res.write(`event: ${type}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  // Allow the running scan to be cancelled: when the client closes the SSE
  // connection (Stop button), `closed` flips and the orchestrator halts.
  options.shouldStop = () => closed;

  // heartbeat so proxies keep the connection open
  const hb = setInterval(() => {
    if (!closed) res.write(': ping\n\n');
  }, 15000);

  try {
    await runScan(target, options, emit);
  } catch (e) {
    emit('error', { message: e.message });
  } finally {
    clearInterval(hb);
    if (!closed) {
      emit('stream:end', {});
      res.end();
    }
  }
});

// Replay a single request so the user can reproduce (and edit) a finding's probe.
// Executes the HTTP request the "curl" represents — not an arbitrary shell command.
app.post('/api/replay', async (req, res) => {
  const { method = 'GET', url, headers = {}, body = null } = req.body || {};
  if (!url || !/^https?:\/\//i.test(url)) {
    res.status(400).json({ error: 'A valid http(s) URL is required.' });
    return;
  }
  const started = Date.now();
  try {
    const r = await httpClient.request(url, {
      method: String(method).toUpperCase(),
      headers: headers && typeof headers === 'object' ? headers : {},
      body: body || null,
      timeout: 15000,
      followRedirects: false,
      maxBodyBytes: 500000,
    });
    res.json({
      ok: true,
      status: r.status,
      statusMessage: r.statusMessage,
      httpVersion: r.httpVersion,
      headers: r.headers,
      setCookies: r.setCookies || [],
      body: (r.body || '').slice(0, 20000),
      truncated: (r.body || '').length > 20000,
      elapsedMs: r.elapsedMs,
      finalUrl: r.finalUrl,
    });
  } catch (e) {
    res.json({ ok: false, error: e.message, elapsedMs: Date.now() - started });
  }
});

app.post('/api/report', (req, res) => {
  const { findings, target, grade, score, intensity } = req.body || {};
  if (!Array.isArray(findings)) {
    res.status(400).json({ error: 'findings array required' });
    return;
  }
  const html = buildReport({ findings, target, grade, score, intensity });
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="smartscan-report-${Date.now()}.html"`
  );
  res.send(html);
});

function clampInt(v, def, min, max) {
  const n = parseInt(v, 10);
  if (Number.isNaN(n)) return def;
  return Math.min(max, Math.max(min, n));
}

app.listen(PORT, () => {
  /* eslint-disable no-console */
  console.log(`\n  Smart Scan running -> http://localhost:${PORT}\n`);
  console.log('  Only scan targets you are authorized to test (e.g. your UAT portals).\n');
});
