/* animations.js — canvas + motion helpers for the Smart Scan console.
 * All effects are hand-rolled (no external libraries) and pause-friendly. */
(function (global) {
  'use strict';

  // ---- Theme accents (updated by theme.js) ------------------------------
  const ACCENTS = {
    rainHead: '#8affc1',            // bright leading glyph
    rain: 'rgba(57, 208, 120, 0.55)', // trailing glyphs
    sweepRgb: '57, 208, 216',       // radar rings + sweep (r,g,b)
    blipRgb: '255, 45, 85',         // radar contact blips (r,g,b)
    ring: '#39d0d8',                // progress ring
  };
  function setAccents(a) {
    if (!a) return;
    Object.assign(ACCENTS, a);
  }

  // ---- Matrix rain background -------------------------------------------
  function MatrixRain(canvas) {
    const ctx = canvas.getContext('2d');
    let cols, drops, fontSize = 14, raf = null, running = false;
    const glyphs = 'アイウエオカキクケコサシスセソ0123456789<>[]{}#$%&*+=/\\';

    function resize() {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      cols = Math.floor(canvas.width / fontSize) + 1;
      drops = new Array(cols).fill(0).map(() => Math.random() * -50);
    }
    function frame() {
      if (!running) return;
      ctx.fillStyle = 'rgba(7, 11, 16, 0.08)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = fontSize + 'px monospace';
      for (let i = 0; i < cols; i++) {
        const ch = glyphs[(Math.random() * glyphs.length) | 0];
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        ctx.fillStyle = Math.random() > 0.975 ? ACCENTS.rainHead : ACCENTS.rain;
        ctx.fillText(ch, x, y);
        if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i] += 0.5;
      }
      raf = requestAnimationFrame(frame);
    }
    this.start = function () { if (running) return; running = true; resize(); frame(); };
    this.stop = function () { running = false; if (raf) cancelAnimationFrame(raf); };
    this.setIntensity = function (a) { canvas.style.opacity = a; };
    window.addEventListener('resize', () => { if (running) resize(); });
  }

  // ---- Radar sweep ------------------------------------------------------
  function Radar(canvas) {
    const ctx = canvas.getContext('2d');
    let angle = 0, raf = null, running = false, blips = [];
    function frame() {
      if (!running) return;
      const w = canvas.width, h = canvas.height, cx = w / 2, cy = h / 2, r = Math.min(cx, cy) - 4;
      ctx.clearRect(0, 0, w, h);
      // rings
      ctx.strokeStyle = `rgba(${ACCENTS.sweepRgb}, 0.25)`;
      ctx.lineWidth = 1;
      for (let i = 1; i <= 3; i++) {
        ctx.beginPath(); ctx.arc(cx, cy, (r * i) / 3, 0, Math.PI * 2); ctx.stroke();
      }
      ctx.beginPath(); ctx.moveTo(cx - r, cy); ctx.lineTo(cx + r, cy); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(cx, cy - r); ctx.lineTo(cx, cy + r); ctx.stroke();
      // sweep gradient
      ctx.save();
      ctx.translate(cx, cy); ctx.rotate(angle);
      const g = ctx.createLinearGradient(0, 0, r, 0);
      g.addColorStop(0, `rgba(${ACCENTS.sweepRgb}, 0.55)`);
      g.addColorStop(1, `rgba(${ACCENTS.sweepRgb}, 0)`);
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.moveTo(0, 0); ctx.arc(0, 0, r, -0.35, 0); ctx.closePath(); ctx.fill();
      ctx.restore();
      // blips
      for (const b of blips) {
        b.life -= 0.01;
        if (b.life <= 0) continue;
        ctx.fillStyle = `rgba(${ACCENTS.blipRgb}, ${b.life})`;
        ctx.beginPath(); ctx.arc(cx + b.x * r, cy + b.y * r, 3, 0, Math.PI * 2); ctx.fill();
      }
      blips = blips.filter((b) => b.life > 0);
      angle += 0.03;
      raf = requestAnimationFrame(frame);
    }
    this.start = function () { if (running) return; running = true; frame(); };
    this.stop = function () { running = false; if (raf) cancelAnimationFrame(raf); };
    this.ping = function () {
      const a = Math.random() * Math.PI * 2, d = 0.3 + Math.random() * 0.6;
      blips.push({ x: Math.cos(a) * d, y: Math.sin(a) * d, life: 1 });
    };
  }

  // ---- Progress ring (draw once per value) ------------------------------
  function drawRing(canvas, pct, color, track) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height, cx = w / 2, cy = h / 2;
    const r = Math.min(cx, cy) - 6;
    ctx.clearRect(0, 0, w, h);
    ctx.lineWidth = 6;
    ctx.strokeStyle = track || 'rgba(255,255,255,0.08)';
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.stroke();
    ctx.strokeStyle = color || ACCENTS.ring;
    ctx.lineCap = 'round';
    ctx.beginPath();
    ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + (Math.PI * 2 * pct) / 100);
    ctx.stroke();
  }

  // ---- Count-up number --------------------------------------------------
  function animateNumber(el, to, dur, suffix) {
    const start = performance.now();
    const from = parseFloat(el.getAttribute('data-val') || '0') || 0;
    function step(now) {
      const t = Math.min(1, (now - start) / (dur || 900));
      const eased = 1 - Math.pow(1 - t, 3);
      const val = Math.round(from + (to - from) * eased);
      el.textContent = val + (suffix || '');
      if (t < 1) requestAnimationFrame(step);
      else el.setAttribute('data-val', String(to));
    }
    requestAnimationFrame(step);
  }

  // ---- Score gauge ------------------------------------------------------
  function drawGauge(canvas, score, color) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height, cx = w / 2, cy = h * 0.72;
    const r = Math.min(cx, cy) - 10;
    ctx.clearRect(0, 0, w, h);
    const start = Math.PI, end = 2 * Math.PI;
    ctx.lineWidth = 12; ctx.lineCap = 'round';
    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    ctx.beginPath(); ctx.arc(cx, cy, r, start, end); ctx.stroke();
    ctx.strokeStyle = color;
    ctx.beginPath();
    ctx.arc(cx, cy, r, start, start + (end - start) * (score / 100));
    ctx.stroke();
  }

  global.SmartAnim = { MatrixRain, Radar, drawRing, animateNumber, drawGauge, setAccents };
})(window);
