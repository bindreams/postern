/* Postern portal frontend script.
 *
 * Drives the Conway's Game of Life background canvas with smooth per-cell fade
 * transitions, the footer counter UI, and the play/pause/+/- controls. Ported
 * verbatim from the locked brainstorming mockup
 * (.superpowers/brainstorm/555-1779133353/content/dashboard-v5.html) and
 * adapted to (a) live in an external file per the CSP "no inline scripts"
 * constraint, (b) attach DOM handlers via addEventListener instead of .onclick
 * for grep-ability, (c) self-bootstrap on DOMContentLoaded so templates do not
 * need an inline init call.
 *
 * Respects `prefers-reduced-motion: reduce` -- the seed renders once and the
 * rAF loop is never armed.
 */

"use strict";

(function () {
  function init() {
    const canvas = document.getElementById("gol-canvas");
    if (!canvas) return;  // gracefully no-op on a future page that doesn't include the canvas
    const tickEl = document.getElementById("gol-tick");
    const liveEl = document.getElementById("gol-live");
    const pauseBtn = document.getElementById("gol-pause");
    const pauseIcon = document.getElementById("gol-pause-icon");
    const reseedBtn = document.getElementById("gol-reseed");
    const slowerBtn = document.getElementById("gol-slower");
    const fasterBtn = document.getElementById("gol-faster");
    const ctx = canvas.getContext("2d");

    const CELL = 14;
    const FILL_R = 255, FILL_G = 255, FILL_B = 255;
    const FILL_ALPHA = 0.06;
    const BORDER_ALPHA = 0.03;
    const SEED_DENSITY = 0.30;

    let cols, rows;
    let prev, grid, next;             // Uint8Array of size cols*rows; 0/1
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    let tick = 0, tickMs = 120;
    let paused = false;
    let tickStartMs = 0;
    let rafId = null;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function allocBuffers() {
      const n = cols * rows;
      prev = new Uint8Array(n);
      grid = new Uint8Array(n);
      next = new Uint8Array(n);
    }

    function resize() {
      const w = Math.max(window.innerWidth, 320), h = Math.max(window.innerHeight, 320);
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = w + "px";
      canvas.style.height = h + "px";
      cols = Math.ceil(w / CELL);
      rows = Math.ceil(h / CELL);
      allocBuffers();
      seed();
    }

    function seed() {
      // prev all-dead so the seed fades in
      prev.fill(0);
      for (let i = 0; i < grid.length; i++) {
        grid[i] = Math.random() < SEED_DENSITY ? 1 : 0;
      }
      tick = 0;
      tickStartMs = performance.now();
      updateCounters(countLive(grid));
      if (reduced) draw(1);
    }

    function countLive(buf) {
      let n = 0;
      for (let i = 0; i < buf.length; i++) n += buf[i];
      return n;
    }

    function advance() {
      let live = 0;
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < cols; x++) {
          let cnt = 0;
          for (let dy = -1; dy <= 1; dy++) {
            for (let dx = -1; dx <= 1; dx++) {
              if (dx === 0 && dy === 0) continue;
              const nx = (x + dx + cols) % cols;
              const ny = (y + dy + rows) % rows;
              cnt += grid[ny * cols + nx];
            }
          }
          const i = y * cols + x;
          const willLive = grid[i] ? (cnt === 2 || cnt === 3) : (cnt === 3);
          next[i] = willLive ? 1 : 0;
          if (willLive) live++;
        }
      }
      // Rotate: prev <- grid, grid <- next, next <- old prev (recycle).
      const oldPrev = prev;
      prev = grid;
      grid = next;
      next = oldPrev;
      tick++;
      updateCounters(live);
    }

    // smoothstep for slightly gentler easing than linear
    function ease(t) { return t * t * (3 - 2 * t); }

    function draw(progress) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const sizePx = CELL * dpr * 0.8;
      const inset = (CELL * dpr - sizePx) / 2;
      const half = 0.5 * dpr;
      const lw = 1 * dpr;
      ctx.lineWidth = lw;
      const e = ease(progress);

      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < cols; x++) {
          const i = y * cols + x;
          const p = prev[i], g = grid[i];
          let alpha;
          if (p && g)        alpha = 1;          // survivor
          else if (!p && g)  alpha = e;          // fade in
          else if (p && !g)  alpha = 1 - e;      // fade out
          else continue;                          // both dead

          const px = x * CELL * dpr + inset;
          const py = y * CELL * dpr + inset;
          ctx.fillStyle   = `rgba(${FILL_R},${FILL_G},${FILL_B},${(FILL_ALPHA   * alpha).toFixed(3)})`;
          ctx.strokeStyle = `rgba(${FILL_R},${FILL_G},${FILL_B},${(BORDER_ALPHA * alpha).toFixed(3)})`;
          ctx.fillRect(px, py, sizePx, sizePx);
          ctx.strokeRect(px + half, py + half, sizePx - lw, sizePx - lw);
        }
      }
    }

    function updateCounters(live) {
      if (tickEl) tickEl.textContent = tick.toLocaleString();
      if (liveEl) liveEl.textContent = live.toLocaleString();
    }

    function frame() {
      const now = performance.now();
      const progress = paused ? 1 : Math.min(1, (now - tickStartMs) / tickMs);
      draw(progress);
      if (!paused && progress >= 1) {
        advance();
        tickStartMs = now;
      }
      rafId = requestAnimationFrame(frame);
    }

    function startLoop() {
      if (rafId == null) rafId = requestAnimationFrame(frame);
    }

    function adjustTick(scale) {
      const now = performance.now();
      const oldProgress = paused ? 0 : Math.min(1, (now - tickStartMs) / tickMs);
      tickMs = Math.min(2000, Math.max(80, tickMs * scale));
      tickStartMs = now - oldProgress * tickMs;
    }

    function setPauseIcon() {
      if (!pauseIcon) return;
      pauseIcon.innerHTML = paused
        ? '<polygon points="6 3 20 12 6 21 6 3"/>'
        : '<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>';
    }

    if (reseedBtn) reseedBtn.addEventListener("click", () => seed());
    if (pauseBtn) pauseBtn.addEventListener("click", () => {
      paused = !paused;
      if (!paused) tickStartMs = performance.now();    // restart fade fresh on resume
      setPauseIcon();
    });
    if (fasterBtn) fasterBtn.addEventListener("click", () => adjustTick(1 / 1.5));
    if (slowerBtn) slowerBtn.addEventListener("click", () => adjustTick(1.5));

    resize();
    if (!reduced) startLoop();
    window.addEventListener("resize", () => {
      resize();
      if (!reduced && rafId == null) startLoop();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
