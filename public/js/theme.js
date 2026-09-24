/* theme.js — theme switcher: applies a data-theme, persists it, and recolors the
 * canvas animations (matrix rain / radar / rings) to match. */
(function (global) {
  'use strict';
  const KEY = 'smartscan.theme';

  // Each theme: label, a preview swatch, and canvas accent colors for SmartAnim.
  const THEMES = {
    cyber: {
      label: 'Cyber Cyan', swatch: '#39d0d8', desc: 'Default neon console',
      accents: { rainHead: '#8affc1', rain: 'rgba(57,208,120,0.55)', sweepRgb: '57, 208, 216', blipRgb: '255, 45, 85', ring: '#39d0d8' },
    },
    hacker: {
      label: 'Hacker', swatch: '#00ff66', desc: 'Hardcore phosphor green',
      accents: { rainHead: '#c6ffd8', rain: 'rgba(0,255,102,0.55)', sweepRgb: '0, 255, 102', blipRgb: '124, 255, 92', ring: '#00ff66' },
    },
    red: {
      label: 'Red Alert', swatch: '#ff2d55', desc: 'Crimson danger console',
      accents: { rainHead: '#ffb3bf', rain: 'rgba(255,60,60,0.5)', sweepRgb: '255, 60, 60', blipRgb: '255, 210, 60', ring: '#ff2d55' },
    },
    synth: {
      label: 'Synthwave', swatch: '#ff2d9b', desc: 'Magenta / purple neon',
      accents: { rainHead: '#ff9ff3', rain: 'rgba(255,45,155,0.5)', sweepRgb: '178, 102, 255', blipRgb: '0, 240, 255', ring: '#ff2d9b' },
    },
    amber: {
      label: 'Amber CRT', swatch: '#ffb000', desc: 'Retro amber terminal',
      accents: { rainHead: '#ffe08a', rain: 'rgba(255,176,0,0.5)', sweepRgb: '255, 176, 0', blipRgb: '255, 120, 0', ring: '#ffb000' },
    },
  };

  function saved() {
    try { return localStorage.getItem(KEY); } catch { return null; }
  }
  function persist(id) {
    try { localStorage.setItem(KEY, id); } catch { /* private mode */ }
  }

  function apply(id) {
    const theme = THEMES[id] || THEMES.cyber;
    document.documentElement.dataset.theme = id in THEMES ? id : 'cyber';
    if (global.SmartAnim && SmartAnim.setAccents) SmartAnim.setAccents(theme.accents);
    // reflect selection in the popover
    document.querySelectorAll('.theme-opt').forEach((el) =>
      el.classList.toggle('sel', el.dataset.theme === document.documentElement.dataset.theme)
    );
    persist(document.documentElement.dataset.theme);
  }

  function buildPopover() {
    const pop = document.getElementById('themePop');
    if (!pop) return;
    pop.innerHTML =
      '<div class="theme-pop-title">CONSOLE THEME</div>' +
      Object.entries(THEMES)
        .map(
          ([id, t]) =>
            `<button class="theme-opt" data-theme="${id}">` +
            `<span class="theme-sw" style="background:${t.swatch}"></span>` +
            `<span class="theme-meta"><b>${t.label}</b><small>${t.desc}</small></span>` +
            `</button>`
        )
        .join('');
    pop.querySelectorAll('.theme-opt').forEach((el) =>
      el.addEventListener('click', () => {
        apply(el.dataset.theme);
        pop.classList.remove('open');
      })
    );
  }

  function init() {
    buildPopover();
    apply(saved() || 'cyber');
    const btn = document.getElementById('themeBtn');
    const pop = document.getElementById('themePop');
    if (btn && pop) {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        pop.classList.toggle('open');
      });
      document.addEventListener('click', (e) => {
        if (!pop.contains(e.target) && e.target !== btn) pop.classList.remove('open');
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  global.SmartTheme = { apply, THEMES };
})(window);
