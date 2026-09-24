'use strict';

/**
 * orchestrator.js — runs the scan phases in order, streams events through an emit()
 * callback, collects findings, and computes an overall A–F grade.
 *
 * emit(type, data) event types:
 *   scan:start   { target, intensity, phases:[{id,title,aggressive}] }
 *   phase:start  { id }
 *   log          { level, message, phase }
 *   check:result { ...finding }
 *   phase:done   { id, counts }
 *   scan:done    { score, grade, counts, findings }
 *   error        { message }
 */

const { URL } = require('url');
const http = require('./httpClient');
const crawler = require('./crawler');
const { gradeFromFindings } = require('./severity');
const { toCurl, toDisplayUrl } = require('./probeUtils');

// Ordered scan phases. moduleFile is loaded lazily.
const PHASES = [
  { id: 'recon', title: 'Reconnaissance', module: 'recon' },
  { id: 'headers', title: 'Security Headers', module: 'headers' },
  { id: 'config', title: 'Configuration & Exposed Files', module: 'configManagement' },
  { id: 'infodisc', title: 'Information Disclosure', module: 'infoDisclosure' },
  { id: 'tls', title: 'Secure Transmission (TLS)', module: 'secureTransmission' },
  { id: 'session', title: 'Session Management', module: 'session' },
  { id: 'cors', title: 'CORS / HTML5', module: 'cors' },
  { id: 'auth', title: 'Authentication', module: 'authentication' },
  { id: 'injection', title: 'Data Validation / Injection', module: 'dataValidation' },
  { id: 'brute', title: 'Brute-Force & Default Creds', module: 'bruteForce', aggressive: true },
  { id: 'fuzz', title: 'Content Discovery (Fuzzing)', module: 'fuzzer', aggressive: true },
  { id: 'dos', title: 'Anti-Automation / Rate Limit', module: 'dos', aggressive: true },
  { id: 'injadv', title: 'Advanced Injection', module: 'injectionAdvanced', aggressive: true },
  { id: 'authatk', title: 'Authentication Attacks', module: 'authAttacks', aggressive: true },
  { id: 'accessctl', title: 'Access Control / IDOR', module: 'accessControl', aggressive: true },
  { id: 'infra', title: 'Infrastructure & Exposure', module: 'infraAttacks', aggressive: true },
  { id: 'dosadv', title: 'Advanced DoS (bounded)', module: 'dosAdvanced', aggressive: true },
];

function normalizeTarget(input) {
  let t = String(input || '').trim();
  if (!/^https?:\/\//i.test(t)) t = 'http://' + t;
  const u = new URL(t); // throws if invalid
  return u.toString();
}

async function runScan(rawTarget, options, emit) {
  const intensity = options.intensity || 'active'; // passive | active | aggressive
  http.resetCounters();
  http.setLimits({
    concurrency: intensity === 'aggressive' ? 16 : 8,
    totalCap: intensity === 'aggressive' ? 20000 : 4000,
  });

  let target;
  try {
    target = normalizeTarget(rawTarget);
  } catch (e) {
    emit('error', { message: `Invalid URL: ${rawTarget}` });
    return;
  }

  // Decide which phases run for this intensity.
  const activePhases = PHASES.filter((p) => {
    if (p.aggressive) return intensity === 'aggressive';
    if (intensity === 'passive') {
      // passive skips active injection
      return p.id !== 'injection';
    }
    return true;
  });

  emit('scan:start', {
    target,
    intensity,
    phases: activePhases.map((p) => ({ id: p.id, title: p.title, aggressive: !!p.aggressive })),
  });

  const findings = [];
  const shared = {};

  const makeCtx = (phaseId) => ({
    target,
    http,
    options,
    shared,
    log: (level, message) => emit('log', { level, message, phase: phaseId }),
    shouldStop: () => !!(options.shouldStop && options.shouldStop()),
    finding: (f) => {
      const rec = { phase: phaseId, ...f };
      // Auto-derive reproduction info from a `request` descriptor.
      if (rec.request) {
        // Show the raw (un-encoded) payload in the URL for easy reading/editing.
        const displayUrl = toDisplayUrl(rec.request) || rec.request.url;
        rec.request = { ...rec.request, url: displayUrl };
        if (!rec.url) rec.url = displayUrl;
        if (!rec.curl) rec.curl = rec.request.command || toCurl(rec.request);
        rec.method = rec.method || rec.request.method || 'GET';
        if (rec.request.param != null && rec.param == null) rec.param = rec.request.param;
        if (rec.request.payload != null && rec.payload == null) rec.payload = rec.request.payload;
        if (rec.request.status != null && rec.httpStatus == null) rec.httpStatus = rec.request.status;
      }
      // Every finding carries at least the scanned target URL for context, and a
      // reproduce command — passive findings fall back to a plain GET of that URL.
      if (!rec.url) rec.url = target;
      if (!rec.curl) rec.curl = toCurl({ method: 'GET', url: rec.url });
      findings.push(rec);
      emit('check:result', rec);
    },
  });

  // Pre-phase: crawl (feeds injection/auth/brute/dos). Skipped in passive-lite? keep it.
  emit('phase:start', { id: 'recon' });
  try {
    const crawlCtx = makeCtx('recon');
    crawlCtx.log('info', `Crawling ${target} (bounded) to map the attack surface...`);
    shared.crawl = await crawler.crawl(target, {
      maxPages: intensity === 'aggressive' ? 40 : 20,
      maxDepth: 2,
      log: (lvl, msg) => crawlCtx.log(lvl, msg),
    });
    crawlCtx.log(
      'info',
      `Crawl found ${shared.crawl.pages.length} page(s), ` +
        `${shared.crawl.paramUrls.length} parameterized URL(s), ` +
        `${shared.crawl.forms.length} form(s).`
    );
  } catch (e) {
    emit('log', { level: 'warn', message: `Crawl failed: ${e.message}`, phase: 'recon' });
    shared.crawl = { pages: [], paramUrls: [], forms: [] };
  }

  // Run each phase's module.
  let completedPhases = 0;
  for (const phase of activePhases) {
    // Honor a stop request (client disconnected / pressed Stop) at phase boundaries.
    if (options.shouldStop && options.shouldStop()) {
      emit('scan:aborted', { completed: completedPhases, total: activePhases.length });
      return;
    }
    // recon phase already opened above (for the crawl); still emit for others.
    if (phase.id !== 'recon') emit('phase:start', { id: phase.id });

    const before = findings.length;
    let mod;
    try {
      mod = require(`./modules/${phase.module}`);
    } catch (e) {
      emit('log', { level: 'warn', message: `Module ${phase.module} load error: ${e.message}`, phase: phase.id });
      emit('phase:done', { id: phase.id, counts: { added: 0 } });
      continue;
    }

    try {
      await mod.run(makeCtx(phase.id));
    } catch (e) {
      emit('log', { level: 'warn', message: `${phase.title} error: ${e.message}`, phase: phase.id });
    }

    const added = findings.slice(before);
    const counts = added.reduce(
      (acc, f) => {
        acc.total++;
        if (f.status === 'fail') acc.fail++;
        else if (f.status === 'warn') acc.warn++;
        else if (f.status === 'pass') acc.pass++;
        else acc.info++;
        return acc;
      },
      { total: 0, fail: 0, warn: 0, pass: 0, info: 0 }
    );
    emit('phase:done', { id: phase.id, counts });
    completedPhases++;
  }

  const grade = gradeFromFindings(findings);
  emit('scan:done', {
    ...grade,
    findings,
    target,
    intensity,
    finishedAt: new Date().toISOString(),
  });
}

module.exports = { runScan, PHASES, normalizeTarget };
