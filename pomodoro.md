---
layout: page
title: "POMO_KERNEL.EXE"
permalink: /pomodoro/
---

<div id="pomo-app-container">
  <style>
    #pomo-app-container {
      --p-bg: #0a0a0a;
      --p-surface: #111111;
      --p-border: #2a2a2a;
      --p-green: #00ff41;
      --p-red: #ff2020;
      --p-grey: #888888;
      --p-white: #f0f0f0;
      --p-font-mono: "Courier New", Courier, monospace;

      font-family: var(--p-font-mono);
      background: var(--p-bg);
      color: var(--p-white);
      padding: 20px;
      border: 1px solid var(--p-border);
      max-width: 900px;
      margin: 0 auto;
      position: relative;
    }

    /* Responsive Flexbox Layout */
    .p-main {
      display: flex;
      flex-direction: column; /* Stacked on mobile */
      gap: 20px;
    }

    @media (min-width: 800px) {
      .p-main { flex-direction: row; } /* Side-by-side on desktop */
    }

    .p-header {
      border-bottom: 1px solid var(--p-border);
      padding-bottom: 15px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }

    .p-title { font-size: 14px; color: var(--p-green); margin: 0; text-transform: uppercase; }
    
    /* Button UI Fix */
    .p-text-btn {
      background: transparent;
      border: 1px solid var(--p-border);
      color: var(--p-grey);
      font-family: var(--p-font-mono);
      font-size: 10px;
      padding: 5px 8px;
      cursor: pointer;
      text-transform: uppercase;
    }

    .p-text-btn.active {
      border-color: var(--p-green);
      color: var(--p-green);
      background: rgba(0, 255, 65, 0.1);
    }

    .p-timer-section, .p-notepad-section {
      flex: 1;
      background: var(--p-surface);
      border: 1px solid var(--p-border);
      padding: 20px;
    }

    .p-notepad-section.hidden { display: none; }

    .p-clock {
      font-size: clamp(40px, 12vw, 70px);
      text-align: center;
      margin: 20px 0;
      color: var(--p-white);
    }

    .p-notepad-area {
      width: 100%;
      background: var(--p-bg);
      color: var(--p-green);
      border: 1px solid var(--p-border);
      font-family: var(--p-font-mono);
      padding: 10px;
      min-height: 250px;
      resize: vertical;
    }

    .p-float {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--p-bg);
      border: 1px solid var(--p-green);
      padding: 10px;
      z-index: 9999;
      display: none;
    }
    .p-float.visible { display: block; }
  </style>

  <div class="p-header">
    <div class="p-title-group">
      <p class="p-title">SYSTEM_PROCESS: POMO_KERNEL.EXE</p>
    </div>
    <div class="p-header-controls">
      <button class="p-text-btn" id="p-toggle-float">[FLOAT]</button>
      <button class="p-text-btn" id="p-toggle-notepad">[NOTES]</button>
      <button class="p-text-btn" id="p-toggle-settings">[CONFIG]</button>
    </div>
  </div>

  <div class="p-main">
    <div class="p-timer-section">
      <div class="p-clock" id="p-clock">25:00</div>
      <div id="p-cycle-label" style="text-align:center; font-size:11px; color:var(--p-grey); margin-bottom:15px;">Cycles: 0 / 4</div>
      <div style="display:flex; gap:10px; justify-content:center;">
        <button class="p-text-btn" id="p-start" style="color:var(--p-green)">[RUN]</button>
        <button class="p-text-btn" id="p-pause">[STOP]</button>
        <button class="p-text-btn" id="p-reset">[RST]</button>
      </div>

      <div id="p-settings-panel" style="display:none; margin-top:20px; border-top:1px solid var(--p-border); padding-top:10px;">
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
          <input type="number" id="p-cfg-work" value="25" style="background:#000; color:#fff; border:1px solid var(--p-border); padding:5px;"/>
          <input type="number" id="p-cfg-cycles" value="4" style="background:#000; color:#fff; border:1px solid var(--p-border); padding:5px;"/>
        </div>
        <button class="p-text-btn" id="p-save-cfg" style="width:100%; margin-top:10px;">[UPDATE_KERNEL]</button>
      </div>
    </div>

    <div class="p-notepad-section hidden" id="p-notepad-section">
      <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
        <span style="font-size:11px; color:var(--p-green)">session_dump.log</span>
        <button class="p-text-btn" id="p-clear-notes" style="font-size:9px;">[WIPE]</button>
      </div>
      <textarea class="p-notepad-area" id="p-notepad" placeholder="Awaiting task data..."></textarea>
    </div>
  </div>

  <div class="p-float" id="p-float">
    <div id="p-float-time" style="font-size:20px; text-align:center;">25:00</div>
    <div style="display:flex; gap:5px; margin-top:5px;">
      <button class="p-text-btn" id="p-float-start" style="font-size:8px;">[RUN]</button>
      <button class="p-text-btn" id="p-float-pause" style="font-size:8px;">[STOP]</button>
    </div>
  </div>

  <script>
    (function () {
      const $ = (id) => document.getElementById(id);
      let workMin = parseInt(localStorage.getItem("p_work")) || 25;
      let targetCycles = parseInt(localStorage.getItem("p_cycles")) || 4;
      let state = { seconds: workMin * 60, running: false, interval: null, audio: null };

      function updateDisplay() {
        const m = Math.floor(state.seconds / 60);
        const s = state.seconds % 60;
        const timeStr = `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
        $("p-clock").textContent = $("p-float-time").textContent = timeStr;
      }

      function beep(freq, dur) {
        if (!state.audio) state.audio = new (window.AudioContext || window.webkitAudioContext)();
        const osc = state.audio.createOscillator();
        const gain = state.audio.createGain();
        osc.connect(gain); gain.connect(state.audio.destination);
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.05, state.audio.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, state.audio.currentTime + dur);
        osc.start(); osc.stop(state.audio.currentTime + dur);
      }

      $("p-start").onclick = $("p-float-start").onclick = () => {
        if (state.running) return;
        state.running = true;
        state.interval = setInterval(() => {
          if (state.seconds <= 0) {
            clearInterval(state.interval); state.running = false;
            beep(880, 0.2); // Double beep for completion
            setTimeout(() => beep(880, 0.2), 250);
            return;
          }
          state.seconds--; updateDisplay();
        }, 1000);
      };

      $("p-pause").onclick = $("p-float-pause").onclick = () => {
        state.running = false; clearInterval(state.interval);
      };

      $("p-toggle-notepad").onclick = () => {
        const n = $("p-notepad-section");
        n.classList.toggle("hidden");
        $("p-toggle-notepad").classList.toggle("active", !n.classList.contains("hidden"));
      };

      $("p-toggle-settings").onclick = () => {
        const s = $("p-settings-panel");
        s.style.display = s.style.display === "none" ? "block" : "none";
        $("p-toggle-settings").classList.toggle("active", s.style.display === "block");
      };

      $("p-toggle-float").onclick = () => {
        const f = $("p-float");
        f.classList.toggle("visible");
        $("p-toggle-float").classList.toggle("active", f.classList.contains("visible"));
      };

      $("p-save-cfg").onclick = () => {
        workMin = parseInt($("p-cfg-work").value);
        targetCycles = parseInt($("p-cfg-cycles").value);
        localStorage.setItem("p_work", workMin);
        localStorage.setItem("p_cycles", targetCycles);
        state.seconds = workMin * 60;
        updateDisplay();
        $("p-settings-panel").style.display = "none";
      };

      updateDisplay();
    })();
  </script>
</div>
