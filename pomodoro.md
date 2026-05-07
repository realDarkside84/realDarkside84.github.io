---
layout: page
title: "POMO_KERNEL.EXE"
permalink: /pomodoro/
---

<link rel="stylesheet" href="/assets/css/pomodoro.css">

<div id="pomo-app-container">

  <div class="p-header">
    <div class="p-title-group">
      <p class="p-title">SYSTEM_PROCESS: POMO_KERNEL.EXE</p>
      <p class="p-tagline">[STATUS: OPTIMIZING_COGNITIVE_OUTPUT]</p>
    </div>
    <div class="p-header-controls">
      <button class="p-text-btn" id="p-toggle-float" title="Toggle Float">
        [FLOAT]
      </button>
      <button class="p-text-btn" id="p-toggle-notepad" title="Toggle Notepad">
        [NOTES]
      </button>
      <button class="p-text-btn" id="p-toggle-settings" title="Settings">
        [CONFIG]
      </button>
      <button class="p-text-btn" id="p-toggle-theme" title="Toggle Theme">
        [THEME]
      </button>
    </div>
  </div>

  <div class="p-main">
    <div class="p-timer-section">
      <div class="p-mode-tabs">
        <button class="p-mode-tab active" data-mode="work">Work</button>
        <button class="p-mode-tab" data-mode="short">Short Break</button>
        <button class="p-mode-tab" data-mode="long">Long Break</button>
      </div>

      <div class="p-clock-wrap">
        <div class="p-clock" id="p-clock">25:00</div>
      </div>

      <div class="p-progress-wrap">
        <div class="p-progress-bar" id="p-progress"></div>
      </div>

      <div class="p-cycles" id="p-cycles"></div>
      <div class="p-cycle-label" id="p-cycle-label">Cycles: 0 / 4</div>

      <div class="p-controls">
        <button class="p-btn p-btn-primary" id="p-start">[START]</button>
        <button class="p-btn" id="p-pause">[PAUSE]</button>
        <button class="p-btn" id="p-reset">[RESET]</button>
        <button class="p-btn" id="p-skip">[SKIP]</button>
      </div>

      <div class="p-settings-panel" id="p-settings-panel">
        <div class="p-settings-grid">
          <div class="p-setting-item">
            <label>Work (min)</label>
            <input type="number" id="p-cfg-work" value="25" min="1" />
          </div>
          <div class="p-setting-item">
            <label>Short (min)</label>
            <input type="number" id="p-cfg-short" value="5" min="1" />
          </div>
          <div class="p-setting-item">
            <label>Long (min)</label>
            <input type="number" id="p-cfg-long" value="15" min="1" />
          </div>
          <div class="p-setting-item">
            <label>Cycles</label>
            <input type="number" id="p-cfg-cycles" value="4" min="1" />
          </div>
        </div>
        <button
          class="p-btn"
          style="width: 100%; margin-top: 15px; justify-content: center"
          id="p-save-cfg"
        >
          [SAVE CONFIG]
        </button>
      </div>

      <div class="p-log" id="p-log">
        <div class="p-log-entry"><span>[BOOT]</span> Kernel initialized.</div>
      </div>
    </div>

    <div class="p-notepad-section hidden" id="p-notepad-section">
      <div class="p-notepad-header">
        <span class="p-notepad-title">Session_Notes.txt</span>
        <div class="p-notepad-tools">
          <input
            type="color"
            class="p-color-picker"
            id="p-note-color"
            value="#00ff41"
            title="Text Color"
          />
          <button class="p-text-btn" id="p-clear-notes" title="Clear Notes">
            [CLEAR]
          </button>
        </div>
      </div>
      <textarea
        class="p-notepad-area"
        id="p-notepad"
        placeholder="Type notes here..."
      ></textarea>
      <div class="p-notepad-footer">
        <span id="p-char-count">0 chars</span>
        <span style="color: var(--p-green)">Auto-save: ON</span>
      </div>
    </div>
  </div>

  <div class="p-float" id="p-float">
    <div class="p-float-time" id="p-float-time">25:00</div>
    <div class="p-float-mode" id="p-float-mode">Work</div>
    <div class="p-float-controls">
      <button class="p-float-btn" id="p-float-start">[START]</button>
      <button class="p-float-btn" id="p-float-pause">[PAUSE]</button>
      <button class="p-float-btn" id="p-float-reset">[RESET]</button>
    </div>
  </div>

</div>

<script src="/assets/js/pomodoro.js"></script>
