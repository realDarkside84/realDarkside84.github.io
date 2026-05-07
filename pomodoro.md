---
layout: page
title: "POMO_KERNEL.EXE"
permalink: /tools/pomodoro/
---

<div id="pomo-app-container">
  <style>
    #pomo-app-container {
      --p-bg: #0a0a0a;
      --p-surface: #111111;
      --p-surface2: #1a1a1a;
      --p-border: #2a2a2a;
      --p-green: #00ff41;
      --p-green-dim: #003b0f;
      --p-red: #ff2020;
      --p-grey: #888888;
      --p-light: #cccccc;
      --p-white: #f0f0f0;
      --p-font-mono: "Courier New", Courier, monospace;

      font-family: var(--p-font-mono);
      background: var(--p-bg);
      color: var(--p-light);
      padding: 15px;
      border: 1px solid var(--p-border);
      border-radius: 4px;
      max-width: 1000px;
      margin: 0 auto;
      position: relative;
      line-height: 1.5;
      overflow: hidden;
    }

    /* Mobile Fix: Stack elements */
    .p-main {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    @media (min-width: 850px) {
      .p-main {
        flex-direction: row;
      }
      #pomo-app-container { padding: 24px; }
    }

    .p-header {
      border-bottom: 1px solid var(--p-border);
      padding-bottom: 12px;
      margin-bottom: 20px;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 10px;
    }

    .p-title-group { flex: 1; min-width: 200px; }
    .p-title {
      font-size: 14px;
      color: var(--p-green);
      letter-spacing: 2px;
      text-transform: uppercase;
      margin: 0;
    }
    .p-tagline { font-size: 10px; color: var(--p-grey); margin: 4px 0 0 0; }

    .p-header-controls { display: flex; gap: 5px; flex-wrap: wrap; }
    
    .p-text-btn {
      background: transparent;
      border: 1px solid var(--p-border);
      color: var(--p-grey);
      font-family: var(--p-font-mono);
      font-size: 10px;
      padding: 4px 6px;
      cursor: pointer;
      border-radius: 2px;
      text-transform: uppercase;
    }

    .p-text-btn.active {
      border-color: var(--p-green);
      color: var(--p-green);
      background: rgba(0, 255, 65, 0.1);
      box-shadow: inset 0 0 5px rgba(0, 255, 65, 0.2);
    }

    .p-timer-section, .p-notepad-section {
      flex: 1;
      background: var(--p-surface);
      border: 1px solid var(--p-border);
      padding: 20px;
      border-radius: 2px;
      display: flex;
      flex-direction: column;
    }

    .p-notepad-section.hidden { display: none; }

    /* Responsive Clock */
    .p-clock {
      font-size: clamp(48px, 15vw, 84px);
      font-weight: bold;
      color: var(--p-white);
      text-align: center;
      margin: 20px 0;
      line-height: 1;
    }

    .p-controls { display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; }
    .p-btn {
      background: transparent;
      border: 1px solid var(--p-border);
      color: var(--p-light);
      font-family: var(--p-font-mono);
      font-size: 11px;
      padding: 8px 12px;
      cursor: pointer;
      text-transform: uppercase;
    }

    .p-notepad-area {
      width: 100%;
      background: var(--p-bg);
      border: 1px solid var(--p-border);
      color: var(--p-green);
      font-family: var(--p-font-mono);
      font-size: 13px;
      padding: 10px;
      min-height: 200px;
      resize: vertical;
    }

    .p-float {
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: 150px;
      background: var(--p-bg);
      border: 1px solid var(--p-green);
      padding: 10px;
      z-index: 1000;
      display: none;
    }
    .p-float.visible { display: block; }
  </style>

  <div class="p-header">
    <div class="p-title-group">
      <p class="p-title">SYSTEM_PROCESS: POMO_KERNEL.EXE</p>
      <p class="p-tagline">[STATUS: OPTIMIZING_COGNITIVE_OUTPUT]</p>
    </div>
    <div class="p-header-controls">
      <button class="p-text-btn" id="p-toggle-float">[FLOAT]</button>
      <button class="p-text-btn" id="p-toggle-notepad">[NOTES]</button>
      <button class="p-text-btn" id="p-toggle-settings">[CONFIG]</button>
    </div>
  </div>

  <div class="p-main">
    <div class="p-timer-section">
      <div class="p-mode-tabs">
        <button class="p-mode-tab active" data-mode="work">Work</button>
        <button class="p-mode-tab" data-mode="short">Short</button>
        <button class="p-mode-tab" data-mode="long">Long</button>
      </div>

      <div class="p-clock" id="p-clock">25:00</div>

      <div class="p-progress-wrap">
        <div class="p-progress-bar" id="p-progress"></div>
      </div>

      <div class="p-cycle-label" id="p-cycle-label">Cycles: 0 / 4</div>

      <div class="p-controls">
        <button class="p-btn" id="p-start">[START]</button>
        <button class="p-btn" id="p-pause">[PAUSE]</button>
        <button class="p-btn" id="p-reset">[RESET]</button>
      </div>

      <div class="p-settings-panel" id="p-settings-panel" style="display:none; margin-top:15px; border-top:1px solid var(--p-border); padding-top:10px;">
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
           <input type="number" id="p-cfg-work" value="25" />
           <input type="number" id="p-cfg-cycles" value="4" />
        </div>
        <button class="p-btn" id="p-save-cfg" style="width:100%; margin-top:10px;">[SAVE]</button>
      </div>
    </div>

    <div class="p-notepad-section hidden" id="p-notepad-section">
      <div class="p-notepad-header">
        <span class="p-notepad-title">session_dump.log</span>
        <button class="p-text-btn" id="p-clear-notes">[WIPE]</button>
      </div>
      <textarea class="p-notepad-area" id="p-notepad" placeholder="Awaiting data..."></textarea>
    </div>
  </div>

  <div class="p-float" id="p-float">
    <div id="p-float-time" style="font-size:24px; text-align:center; font-weight:bold;">25:00</div>
    <div class="p-float-controls" style="display:flex; gap:5px; margin-top:5px;">
      <button class="p-float-btn" id="p-float-start" style="flex:1; font-size:10px;">[START]</button>
      <button class="p-float-btn" id="p-float-pause" style="flex:1; font-size:10px;">[STOP]</button>
    </div>
  </div>

  <script>
    (function () {
      const $ = (id) => document.getElementById(id);
      
      const cfg = {
        work: parseInt(localStorage.getItem("p_work")) || 25,
        cycles: parseInt(localStorage.getItem("p_cycles")) || 4
      };

      let state = {
        mode: "work",
        seconds: cfg.work * 60,
        running: false,
        interval: null
      };

      function updateDisplay() {
        const m = Math.floor(state.seconds / 60);
        const s = state.seconds % 60;
        const timeStr = `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
        $("p-clock").textContent = $("p-float-time").textContent = timeStr;
      }

      function startTimer() {
        if (state.running) return;
        state.running = true;
        state.interval = setInterval(() => {
          if (state.seconds <= 0) {
            clearInterval(state.interval);
            state.running = false;
            return;
          }
          state.seconds--;
          updateDisplay();
        }, 1000);
      }

      function pauseTimer() {
        state.running = false;
        clearInterval(state.interval);
      }

      function toggleNotepad() {
        const section = $("p-notepad-section");
        const btn = $("p-toggle-notepad");
        section.classList.toggle("hidden");
        btn.classList.toggle("active", !section.classList.contains("hidden"));
      }

      // Initialize
      $("p-start").onclick = $("p-float-start").onclick = startTimer;
      $("p-pause").onclick = $("p-float-pause").onclick = pauseTimer;
      $("p-toggle-notepad").onclick = toggleNotepad;
      $("p-toggle-settings").onclick = () => {
         const p = $("p-settings-panel");
         p.style.display = p.style.display === "none" ? "block" : "none";
         $("p-toggle-settings").classList.toggle("active", p.style.display === "block");
      };
      $("p-toggle-float").onclick = () => {
         const f = $("p-float");
         f.classList.toggle("visible");
         $("p-toggle-float").classList.toggle("active", f.classList.contains("visible"));
      };

      updateDisplay();
    })();
  </script>
</div>
