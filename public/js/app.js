/* app.js — Smart Scan front-end controller: streaming scan + live animations. */
(function () {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  // ---- Background + visuals ----
  const matrix = new SmartAnim.MatrixRain($('#matrix'));
  const radar = new SmartAnim.Radar($('#radar'));

  // ---- Tabs ----
  $$('.tab').forEach((t) =>
    t.addEventListener('click', () => {
      $$('.tab').forEach((x) => x.classList.remove('active'));
      t.classList.add('active');
      const pane = t.dataset.pane;
      $('#scannerPane').style.display = pane === 'scanner' ? 'block' : 'none';
      $('#siteinfoPane').classList.toggle('show', pane === 'siteinfo');
      $('#checklistPane').classList.toggle('show', pane === 'checklist');
      if (pane === 'checklist') window.SmartChecklist.ensureLoaded();
      if (pane === 'siteinfo') window.SmartSiteInfo.init();
    })
  );

  // ---- Intensity selector ----
  let intensity = 'active';
  $$('#intensity button').forEach((b) =>
    b.addEventListener('click', () => {
      $$('#intensity button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      intensity = b.dataset.v;
      const agg = intensity === 'aggressive';
      $('#advOpts').classList.toggle('show', agg);
      $('#aggWarn').style.display = agg ? 'block' : 'none';
    })
  );

  // ---- Auth gate + input enable ----
  const urlInput = $('#url');
  const authz = $('#authz');
  const startBtn = $('#startBtn');
  const stopBtn = $('#stopBtn');
  let aborted = false;
  function refreshStart() {
    startBtn.disabled = !(authz.checked && urlInput.value.trim().length > 3);
  }
  urlInput.addEventListener('input', refreshStart);
  authz.addEventListener('change', refreshStart);
  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !startBtn.disabled) startScan();
  });
  startBtn.addEventListener('click', startScan);
  stopBtn.addEventListener('click', abortScan);

  function abortScan() {
    if (!es) return;
    aborted = true;
    stopBtn.disabled = true;
    logLine('warn', '⛔ Scan stopped by user.');
    // Closing the EventSource drops the SSE connection; the server sees the close and
    // halts the scan at the next phase boundary (shouldStop).
    es.close();
    es = null;
    // Mark any still-running phase cards as stopped.
    document.querySelectorAll('.pcard[data-state="running"]').forEach((card) => {
      card.dataset.state = 'stopped';
      const meta = card.querySelector('.pc-meta');
      if (meta) meta.textContent = 'stopped';
      const badge = card.querySelector('.pc-badge');
      if (badge) badge.textContent = '■';
    });
    finishStream(true);
  }

  // ---- Terminal ----
  const term = $('#term');
  let cursorEl = null;
  const MAX_LINES = 600;
  function logLine(level, message) {
    if (cursorEl) cursorEl.remove();
    const time = new Date().toLocaleTimeString('en-GB', { hour12: false });
    const line = document.createElement('div');
    line.className = 'line' + (level === 'vuln' ? ' vuln' : '');
    const tag = { info: 'INFO', ok: ' OK ', warn: 'WARN', vuln: 'VULN', debug: 'DBG ' }[level] || 'LOG ';
    line.innerHTML =
      `<span class="t">[${time}]</span> ` +
      `<span class="lvl lvl-${level}">${tag}</span> ` +
      escapeHtml(message);
    term.appendChild(line);
    cursorEl = document.createElement('span');
    cursorEl.className = 'cursor';
    term.appendChild(cursorEl);
    while (term.childElementCount > MAX_LINES + 1) term.removeChild(term.firstChild);
    term.scrollTop = term.scrollHeight;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  // ---- State ----
  let es = null;
  let scanComplete = false;
  let phases = [];
  let phaseDone = 0;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, pass: 0 };
  let allFindings = [];
  let lastMeta = {};

  // ---- Severity filter ----
  const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
  const activeSeverities = new Set(SEVS);
  const feedCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  function sevBucket(f) {
    return ['critical', 'high', 'medium', 'low'].includes(f.severity) ? f.severity : 'info';
  }
  function applyFilters() {
    document.querySelectorAll('#findings .finding').forEach((el) => {
      el.style.display = activeSeverities.has(el.dataset.sev) ? '' : 'none';
    });
  }
  $$('#findingFilters .f-chip[data-sev]').forEach((chip) => {
    chip.addEventListener('click', () => {
      const sev = chip.dataset.sev;
      if (activeSeverities.has(sev)) { activeSeverities.delete(sev); chip.classList.remove('active'); }
      else { activeSeverities.add(sev); chip.classList.add('active'); }
      applyFilters();
    });
  });
  $('#fChipAll').addEventListener('click', () => {
    SEVS.forEach((s) => activeSeverities.add(s));
    $$('#findingFilters .f-chip[data-sev]').forEach((c) => c.classList.add('active'));
    applyFilters();
  });

  function resetState() {
    if (es) { es.close(); es = null; }
    term.innerHTML = '';
    cursorEl = null;
    phases = [];
    phaseDone = 0;
    Object.keys(counts).forEach((k) => (counts[k] = 0));
    Object.keys(feedCounts).forEach((k) => (feedCounts[k] = 0));
    SEVS.forEach((s) => { const el = $('#fn-' + s); if (el) el.textContent = '0'; });
    allFindings = [];
    $('#phases').innerHTML = '';
    $('#findings').innerHTML = '';
    $('#findingsWrap').classList.add('hidden');
    $('#summary').classList.remove('show');
    ['cCrit', 'cHigh', 'cMed', 'cPass'].forEach((id) => {
      const el = $('#' + id); el.setAttribute('data-val', '0'); el.textContent = '0';
    });
    setProgress(0);
  }

  function setProgress(pct) {
    SmartAnim.drawRing($('#progressRing'), pct, pct >= 100 ? '#3ddc97' : '#39d0d8');
    const p = $('#progressPct');
    p.textContent = Math.round(pct) + '%';
  }

  function startScan() {
    resetState();
    scanComplete = false;
    $('#dash').classList.add('show');
    matrix.start();
    $('#matrix').style.opacity = '0.22';
    radar.start();
    startBtn.disabled = true;
    startBtn.textContent = '● Scanning…';
    stopBtn.style.display = '';
    stopBtn.disabled = false;
    aborted = false;
    $('#termTitle').textContent = 'smartscan@console — running';

    const params = new URLSearchParams({
      url: urlInput.value.trim(),
      intensity,
      maxBrute: $('#maxBrute').value || '25',
      maxFuzz: $('#maxFuzz').value || '120',
      dosRequests: $('#dosRequests').value || '30',
      maxIdor: $('#maxIdor').value || '15',
      maxBodyKb: $('#maxBodyKb').value || '1024',
    });
    es = new EventSource('/api/scan/stream?' + params.toString());

    es.addEventListener('scan:start', (e) => onScanStart(JSON.parse(e.data)));
    es.addEventListener('phase:start', (e) => onPhaseStart(JSON.parse(e.data)));
    es.addEventListener('log', (e) => { const d = JSON.parse(e.data); logLine(d.level, d.message); });
    es.addEventListener('check:result', (e) => onFinding(JSON.parse(e.data)));
    es.addEventListener('phase:done', (e) => onPhaseDone(JSON.parse(e.data)));
    es.addEventListener('scan:done', (e) => onScanDone(JSON.parse(e.data)));
    es.addEventListener('scan:aborted', (e) => {
      const d = JSON.parse(e.data);
      logLine('warn', `Scan aborted (${d.completed}/${d.total} phases completed).`);
      finishStream(true);
    });
    es.addEventListener('error', (e) => {
      if (e.data) { const d = JSON.parse(e.data); logLine('vuln', 'ERROR: ' + d.message); }
    });
    es.addEventListener('stream:end', () => finishStream());
    es.onerror = () => {
      // EventSource auto-reconnects on close; once the scan is done, stop it so a
      // completed scan is never silently restarted.
      if (scanComplete) finishStream();
    };
  }

  function onScanStart(d) {
    lastMeta = { target: d.target, intensity: d.intensity };
    logLine('info', `Scan started against ${d.target} [intensity: ${d.intensity}]`);
    phases = d.phases;
    const grid = $('#phases');
    grid.innerHTML = '';
    for (const p of phases) {
      const card = document.createElement('div');
      card.className = 'pcard';
      card.id = 'ph-' + p.id;
      card.dataset.state = 'pending';
      card.innerHTML =
        `<div class="pc-title">${escapeHtml(p.title)} ${p.aggressive ? '<span class="pc-agg">AGGR</span>' : ''}</div>` +
        `<div class="pc-meta" id="phm-${p.id}">queued</div>` +
        `<div class="pc-bar"><div class="pc-fill"></div></div>` +
        `<div class="pc-badge" id="phb-${p.id}"></div>`;
      grid.appendChild(card);
    }
  }

  function onPhaseStart(d) {
    const card = $('#ph-' + d.id);
    if (!card) return;
    card.dataset.state = 'running';
    $('#phm-' + d.id).textContent = 'scanning…';
    $('#phb-' + d.id).textContent = '◉';
    const p = phases.find((x) => x.id === d.id);
    $('#termTitle').textContent = 'smartscan@console — ' + (p ? p.title : d.id);
  }

  function onPhaseDone(d) {
    const card = $('#ph-' + d.id);
    phaseDone++;
    if (card) {
      const c = d.counts || {};
      card.dataset.state = c.fail > 0 ? 'issues' : 'done';
      $('#phm-' + d.id).textContent =
        `${c.total || 0} checks · ${c.fail || 0} issues`;
      $('#phb-' + d.id).textContent = c.fail > 0 ? '✕' : '✓';
    }
    setProgress(phases.length ? (phaseDone / phases.length) * 100 : 100);
  }

  function onFinding(f) {
    allFindings.push(f);
    // counters
    if (f.status === 'pass') counts.pass++;
    else if (f.status === 'fail' || f.status === 'warn') counts[f.severity] = (counts[f.severity] || 0) + 1;
    updateStats();
    if (f.status === 'fail' || f.status === 'warn') radar.ping();

    // Only surface actionable items (fail/warn) plus notable info in the feed.
    if (f.status === 'pass') return;
    $('#findingsWrap').classList.remove('hidden');
    const wrap = $('#findings');
    const sev = f.severity || 'info';
    // filter bucket + live chip count
    const bucket = sevBucket(f);
    feedCounts[bucket]++;
    const nEl = $('#fn-' + bucket);
    if (nEl) nEl.textContent = feedCounts[bucket];
    const el = document.createElement('div');
    el.className = `finding sev-${sev} ${f.status === 'pass' ? 'pass' : ''} collapsed`;
    el.dataset.sev = bucket;
    if (!activeSeverities.has(bucket)) el.style.display = 'none';

    // Details grid rows (only render rows we actually have)
    const rows = [];
    if (f.url) rows.push(`<div class="fd-k">URL</div><div class="fd-v"><a href="${escapeHtml(f.url)}" target="_blank" rel="noopener">${escapeHtml(f.url)}</a></div>`);
    if (f.method) rows.push(`<div class="fd-k">Method</div><div class="fd-v">${escapeHtml(f.method)}</div>`);
    if (f.param) rows.push(`<div class="fd-k">Parameter</div><div class="fd-v">${escapeHtml(f.param)}</div>`);
    if (f.payload) rows.push(`<div class="fd-k">Payload</div><div class="fd-v">${escapeHtml(f.payload)}</div>`);
    if (f.httpStatus != null) rows.push(`<div class="fd-k">HTTP status</div><div class="fd-v">${escapeHtml(f.httpStatus)}</div>`);
    const detailGrid = rows.length ? `<div class="f-detail">${rows.join('')}</div>` : '';

    const repro = f.curl
      ? `<div class="f-repro"><div class="f-repro-head"><span>Reproduce</span>` +
        `<span class="f-repro-btns"><button class="f-run" type="button">▶ Reproduce</button>` +
        `<button class="f-copy" type="button">⧉ Copy</button></span></div>` +
        `<pre class="f-curl">${escapeHtml(f.curl)}</pre></div>`
      : '';

    el.innerHTML =
      `<div class="sev-badge ${sev}">${(f.status === 'fail' || f.status === 'warn') ? sev : f.status}</div>` +
      `<div class="f-body">` +
      `<div class="f-cat">${escapeHtml(f.category)}</div>` +
      `<div class="f-title">${escapeHtml(f.title)} <span class="f-caret">▾</span></div>` +
      `<div class="f-ev">${escapeHtml(f.evidence || '')}</div>` +
      detailGrid +
      repro +
      `<div class="f-rem"><b>Fix:</b> ${escapeHtml(f.remediation || '')}` +
      (f.reference ? ` · <a href="${escapeHtml(f.reference)}" target="_blank" rel="noopener" class="f-ref">ref</a>` : '') +
      `</div></div>`;

    // Whole card toggles expand/collapse; links/buttons inside don't.
    el.addEventListener('click', (ev) => {
      if (ev.target.closest('a') || ev.target.closest('button')) return;
      el.classList.toggle('collapsed');
    });
    const copyBtn = el.querySelector('.f-copy');
    if (copyBtn) {
      copyBtn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        copyText(f.curl);
        copyBtn.textContent = '✓ Copied';
        setTimeout(() => { copyBtn.textContent = '⧉ Copy'; }, 1400);
      });
    }
    const runBtn = el.querySelector('.f-run');
    if (runBtn) {
      runBtn.addEventListener('click', (ev) => { ev.stopPropagation(); openRepro(f); });
    }
    wrap.prepend(el);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  }
  function fallbackCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    } catch { /* ignore */ }
  }

  // ---- Reproduce modal ----
  const reproModal = $('#reproModal');
  const reproEls = {
    title: $('#reproTitle'), method: $('#reproMethod'), url: $('#reproUrl'),
    headers: $('#reproHeaders'), body: $('#reproBody'), bodyWrap: $('#reproBodyWrap'),
    cmd: $('#reproCmd'), out: $('#reproOut'), outStatus: $('#reproOutStatus'), run: $('#reproRun'),
  };
  function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
  function parseHeaders(text) {
    const h = {};
    (text || '').split('\n').forEach((line) => {
      const i = line.indexOf(':');
      if (i > 0) { const k = line.slice(0, i).trim(); const v = line.slice(i + 1).trim(); if (k) h[k] = v; }
    });
    return h;
  }
  function headersToText(h) {
    return Object.entries(h || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  }
  function buildReproCmd() {
    const method = reproEls.method.value.toUpperCase();
    const url = reproEls.url.value.trim();
    const headers = parseHeaders(reproEls.headers.value);
    const body = reproEls.body.value;
    const parts = ['curl', '-i', '-sk'];
    if (method !== 'GET') parts.push('-X', method);
    for (const k of Object.keys(headers)) parts.push('-H', shq(`${k}: ${headers[k]}`));
    if (body && method !== 'GET') {
      if (!headers['Content-Type'] && !headers['content-type']) parts.push('-H', shq('Content-Type: application/x-www-form-urlencoded'));
      parts.push('--data', shq(body));
    }
    parts.push(shq(url));
    reproEls.cmd.textContent = parts.join(' ');
  }
  function toggleBody() {
    const show = reproEls.method.value !== 'GET' || reproEls.body.value.trim() !== '';
    reproEls.bodyWrap.style.display = show ? '' : 'none';
  }
  function openRepro(f) {
    const req = f.request || { method: f.method || 'GET', url: f.url, headers: {}, body: '' };
    reproEls.title.textContent = 'reproduce — ' + (f.title || '');
    reproEls.method.value = (req.method || 'GET').toUpperCase();
    reproEls.url.value = req.url || f.url || '';
    reproEls.headers.value = headersToText(req.headers);
    reproEls.body.value = req.body || '';
    reproEls.out.textContent = 'Edit the request above and press Run.';
    reproEls.out.className = 'repro-out';
    reproEls.outStatus.textContent = 'Response';
    toggleBody();
    buildReproCmd();
    reproModal.classList.add('open');
    reproModal.setAttribute('aria-hidden', 'false');
    setTimeout(() => reproEls.url.focus(), 50);
  }
  function closeRepro() {
    reproModal.classList.remove('open');
    reproModal.setAttribute('aria-hidden', 'true');
  }
  async function runRepro() {
    const payload = {
      method: reproEls.method.value.toUpperCase(),
      url: reproEls.url.value.trim(),
      headers: parseHeaders(reproEls.headers.value),
      body: reproEls.body.value || null,
    };
    reproEls.run.disabled = true;
    reproEls.out.textContent = '⏳ sending request…';
    reproEls.out.className = 'repro-out';
    try {
      const res = await fetch('/api/replay', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      });
      const d = await res.json();
      if (!d.ok) {
        reproEls.outStatus.textContent = 'Error';
        reproEls.out.className = 'repro-out err';
        reproEls.out.textContent = '✗ ' + (d.error || 'request failed');
      } else {
        const statusClass = d.status >= 500 ? 'err' : d.status >= 400 ? 'warnc' : d.status >= 300 ? 'redir' : 'okc';
        reproEls.outStatus.innerHTML = `HTTP ${d.status} ${escapeHtml(d.statusMessage || '')} · ${d.elapsedMs}ms`;
        const hdrs = Object.entries(d.headers || {}).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join('\n');
        reproEls.out.className = 'repro-out ' + statusClass;
        reproEls.out.textContent =
          `HTTP/${d.httpVersion || '1.1'} ${d.status} ${d.statusMessage || ''}\n${hdrs}\n\n${d.body || ''}` +
          (d.truncated ? '\n\n… [response truncated]' : '');
      }
    } catch (e) {
      reproEls.outStatus.textContent = 'Error';
      reproEls.out.className = 'repro-out err';
      reproEls.out.textContent = '✗ ' + e.message;
    } finally {
      reproEls.run.disabled = false;
    }
  }
  ['input', 'change'].forEach((evt) => {
    reproEls.method.addEventListener(evt, () => { toggleBody(); buildReproCmd(); });
    reproEls.url.addEventListener(evt, buildReproCmd);
    reproEls.headers.addEventListener(evt, buildReproCmd);
    reproEls.body.addEventListener(evt, () => { toggleBody(); buildReproCmd(); });
  });
  reproEls.run.addEventListener('click', runRepro);
  $('#reproClose').addEventListener('click', closeRepro);
  reproModal.addEventListener('click', (e) => { if (e.target === reproModal) closeRepro(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && reproModal.classList.contains('open')) closeRepro(); });

  function updateStats() {
    SmartAnim.animateNumber($('#cCrit'), counts.critical, 500);
    SmartAnim.animateNumber($('#cHigh'), counts.high, 500);
    SmartAnim.animateNumber($('#cMed'), counts.medium, 500);
    SmartAnim.animateNumber($('#cPass'), counts.pass, 500);
  }

  function onScanDone(d) {
    scanComplete = true;
    lastMeta = { ...lastMeta, grade: d.grade, score: d.score };
    setProgress(100);
    logLine('ok', `Scan complete — grade ${d.grade} (score ${d.score}/100), ${allFindings.length} checks recorded.`);
    const gradeColor = d.grade === 'A' ? '#3ddc97' : d.grade === 'F' ? '#ff2d55' : d.grade === 'B' ? '#8affc1' : '#ffcc00';
    $('#gradeBig').textContent = d.grade;
    $('#gradeBig').style.color = gradeColor;
    SmartAnim.drawGauge($('#gauge'), d.score, gradeColor);
    const failCount = allFindings.filter((f) => f.status === 'fail').length;
    $('#summaryMsg').innerHTML =
      `Scanned <b style="color:var(--cyan)">${escapeHtml(d.target)}</b> at <b>${escapeHtml(d.intensity)}</b> intensity.<br>` +
      `<b style="color:${gradeColor}">${failCount}</b> issue(s) need attention · ` +
      `${counts.critical} critical, ${counts.high} high, ${counts.medium} medium.`;
    $('#summary').classList.add('show');
  }

  function finishStream(wasAborted) {
    if (es) { es.close(); es = null; }
    startBtn.disabled = false;
    startBtn.textContent = '▶ Start Scan';
    stopBtn.style.display = 'none';
    stopBtn.disabled = false;
    $('#termTitle').textContent = 'smartscan@console — ' + (wasAborted || aborted ? 'stopped' : 'done');
    if (cursorEl) { cursorEl.remove(); cursorEl = null; }
    radar.stop();
    $('#matrix').style.opacity = '0.10';
  }

  // ---- Report downloads ----
  $('#downloadJson').addEventListener('click', () => {
    const data = JSON.stringify({ ...lastMeta, findings: allFindings }, null, 2);
    downloadBlob(new Blob([data], { type: 'application/json' }), 'smartscan-report.json');
  });
  $('#downloadHtml').addEventListener('click', async () => {
    const res = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...lastMeta, findings: allFindings }),
    });
    const blob = await res.blob();
    downloadBlob(blob, 'smartscan-report.html');
  });
  $('#rescanBtn').addEventListener('click', () => {
    $('#summary').classList.remove('show');
    urlInput.focus();
  });
  function downloadBlob(blob, name) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  // draw initial empty ring
  setProgress(0);
  matrix.start();
  $('#matrix').style.opacity = '0.08';
})();
