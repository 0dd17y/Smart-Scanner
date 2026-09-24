/* checklist.js — interactive OWASP manual checklist with localStorage persistence. */
(function (global) {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const KEY = 'smartscan.checklist.v1';
  let loaded = false;
  let owaspRef = '#';

  function loadState() {
    try { return JSON.parse(localStorage.getItem(KEY) || '{}'); }
    catch { return {}; }
  }
  function saveState(state) {
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch { /* private mode */ }
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  async function ensureLoaded() {
    if (loaded) return;
    loaded = true;
    let data;
    try {
      const res = await fetch('/api/checklist');
      data = await res.json();
    } catch (e) {
      $('#checklist').innerHTML = '<p style="color:var(--red)">Failed to load checklist.</p>';
      return;
    }
    owaspRef = data.owasp || '#';
    render(data.groups);
  }

  function render(groups) {
    const state = loadState();
    const host = $('#checklist');
    host.innerHTML = '';
    let total = 0;

    for (const g of groups) {
      const done = g.items.filter((i) => state[i.id]).length;
      total += g.items.length;
      const details = document.createElement('details');
      details.className = 'cl-group panel';
      details.innerHTML =
        `<summary><span>${escapeHtml(g.category)}</span>` +
        `<span class="g-count" id="gc-${slug(g.category)}">${done}/${g.items.length}</span></summary>`;
      for (const item of g.items) {
        const row = document.createElement('div');
        row.className = 'cl-item' + (item.auto ? ' auto' : '') + (state[item.id] ? ' done' : '');
        row.innerHTML =
          `<input type="checkbox" id="ck-${item.id}" ${state[item.id] ? 'checked' : ''}>` +
          `<label for="ck-${item.id}">${escapeHtml(item.text)}` +
          (item.auto ? '<span class="badge-auto">AUTO</span>' : '') +
          `</label>`;
        const cb = row.querySelector('input');
        cb.addEventListener('change', () => {
          const st = loadState();
          st[item.id] = cb.checked;
          saveState(st);
          row.classList.toggle('done', cb.checked);
          updateCounts(groups);
        });
        details.appendChild(row);
      }
      host.appendChild(details);
    }
    $('#clTotal').textContent = total;
    updateCounts(groups);
  }

  function updateCounts(groups) {
    const state = loadState();
    let done = 0;
    for (const g of groups) {
      const d = g.items.filter((i) => state[i.id]).length;
      done += d;
      const el = document.getElementById('gc-' + slug(g.category));
      if (el) el.textContent = `${d}/${g.items.length}`;
    }
    $('#clDone').textContent = done;
  }

  function slug(s) { return s.toLowerCase().replace(/[^a-z0-9]+/g, '-'); }

  // Reset button
  document.addEventListener('DOMContentLoaded', () => {
    const btn = $('#clReset');
    if (btn) btn.addEventListener('click', () => {
      if (!confirm('Clear all checklist progress?')) return;
      saveState({});
      loaded = false;
      ensureLoaded();
    });
  });

  global.SmartChecklist = { ensureLoaded };
})(window);
