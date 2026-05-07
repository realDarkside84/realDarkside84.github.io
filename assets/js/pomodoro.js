(function () {
  const $ = (id) => document.getElementById(id);

  const cfg = {
    work: parseInt(localStorage.getItem("p_work")) || 25,
    short: parseInt(localStorage.getItem("p_short")) || 5,
    long: parseInt(localStorage.getItem("p_long")) || 15,
    cycles: parseInt(localStorage.getItem("p_cycles")) || 4,
  };

  let state = {
    mode: "work",
    seconds: cfg.work * 60,
    total: cfg.work * 60,
    running: false,
    completed: 0,
    interval: null,
    audioCtx: null,
  };

  const el = {
    clock: $("p-clock"),
    progress: $("p-progress"),
    cycles: $("p-cycles"),
    cycleLabel: $("p-cycle-label"),
    log: $("p-log"),
    notepad: $("p-notepad"),
    noteColor: $("p-note-color"),
    charCount: $("p-char-count"),
    float: $("p-float"),
    floatTime: $("p-float-time"),
    floatMode: $("p-float-mode"),
    notepadSection: $("p-notepad-section"),
  };

  function init() {
    updateDisplay();
    renderCycles();
    loadNotes();
    setupDraggable();

    $("p-start").onclick = $("p-float-start").onclick = startTimer;
    $("p-pause").onclick = $("p-float-pause").onclick = pauseTimer;
    $("p-reset").onclick = $("p-float-reset").onclick = resetTimer;
    $("p-skip").onclick = skipSession;

    $("p-toggle-float").onclick = () =>
      el.float.classList.toggle("visible");
    $("p-toggle-notepad").onclick = toggleNotepad;
    $("p-toggle-settings").onclick = () =>
      $("p-settings-panel").classList.toggle("open");
    $("p-toggle-theme").onclick = toggleTheme;

    $("p-clear-notes").onclick = () => {
      el.notepad.value = "";
      updateCharCount();
      saveNotes();
    };
    el.notepad.oninput = () => {
      updateCharCount();
      saveNotes();
    };
    el.noteColor.oninput = (e) => {
      el.notepad.style.color = e.target.value;
      localStorage.setItem("p_note_color", e.target.value);
    };

    $("p-save-cfg").onclick = saveConfig;

    document.querySelectorAll(".p-mode-tab").forEach((tab) => {
      tab.onclick = () => setMode(tab.dataset.mode);
    });

    const savedColor = localStorage.getItem("p_note_color");
    if (savedColor) {
      el.noteColor.value = savedColor;
      el.notepad.style.color = savedColor;
    }
  }

  function startTimer() {
    if (state.running) return;
    state.running = true;
    state.interval = setInterval(tick, 1000);
    addLog("Session started.");
  }

  function pauseTimer() {
    state.running = false;
    clearInterval(state.interval);
    addLog("Session paused.");
  }

  function resetTimer() {
    pauseTimer();
    const dur =
      state.mode === "work"
        ? cfg.work
        : state.mode === "short"
        ? cfg.short
        : cfg.long;
    state.seconds = dur * 60;
    state.total = dur * 60;
    updateDisplay();
    addLog("Timer reset.");
  }

  function tick() {
    if (state.seconds <= 0) {
      onComplete();
      return;
    }
    state.seconds--;
    updateDisplay();
  }

  function onComplete() {
    pauseTimer();
    if (state.mode === "work") {
      state.completed++;
      beep(880, 0.2);
      setTimeout(() => beep(880, 0.2), 250);
      if (state.completed % cfg.cycles === 0) setMode("long");
      else setMode("short");
    } else {
      beep(440, 0.8);
      setMode("work");
    }
    renderCycles();
  }

  function setMode(mode) {
    state.mode = mode;
    const dur =
      mode === "work" ? cfg.work : mode === "short" ? cfg.short : cfg.long;
    state.seconds = dur * 60;
    state.total = dur * 60;
    document
      .querySelectorAll(".p-mode-tab")
      .forEach((t) =>
        t.classList.toggle("active", t.dataset.mode === mode)
      );
    updateDisplay();
    addLog(`Switched to ${mode}.`);
  }

  function skipSession() {
    addLog("Session skipped.");
    onComplete();
  }

  function updateDisplay() {
    const m = Math.floor(state.seconds / 60);
    const s = state.seconds % 60;
    const timeStr = `${String(m).padStart(2, "0")}:${String(s).padStart(
      2,
      "0"
    )}`;
    el.clock.textContent = el.floatTime.textContent = timeStr;
    el.progress.style.width = (state.seconds / state.total) * 100 + "%";
    el.floatMode.textContent = state.mode;
    el.clock.classList.toggle(
      "warning",
      state.mode === "work" && state.seconds < 60
    );
    document.title = `(${timeStr}) POMO_KERNEL`;
  }

  function renderCycles() {
    el.cycles.innerHTML = "";
    for (let i = 0; i < cfg.cycles; i++) {
      const dot = document.createElement("div");
      dot.className =
        "p-cycle-dot" + (i < state.completed % cfg.cycles ? " filled" : "");
      el.cycles.appendChild(dot);
    }
    el.cycleLabel.textContent = `Cycles: ${state.completed} / ${cfg.cycles}`;
  }

  function addLog(msg) {
    const now = new Date();
    const ts = now.toTimeString().split(" ")[0];
    const entry = document.createElement("div");
    entry.className = "p-log-entry";
    entry.innerHTML = `<span>[${ts}]</span> ${msg}`;
    el.log.prepend(entry);
  }

  function toggleNotepad() {
    el.notepadSection.classList.toggle("hidden");
    const isHidden = el.notepadSection.classList.contains("hidden");
    $("p-toggle-notepad").classList.toggle("active", !isHidden);
  }

  function toggleTheme() {
    const container = $("pomo-app-container");
    container.classList.toggle("light-mode");
    const isLight = container.classList.contains("light-mode");
    $("p-toggle-theme").innerHTML = isLight
      ? "[THEME: LIGHT]"
      : "[THEME: DARK]";
  }

  function saveConfig() {
    cfg.work = parseInt($("p-cfg-work").value);
    cfg.short = parseInt($("p-cfg-short").value);
    cfg.long = parseInt($("p-cfg-long").value);
    cfg.cycles = parseInt($("p-cfg-cycles").value);
    localStorage.setItem("p_work", cfg.work);
    localStorage.setItem("p_short", cfg.short);
    localStorage.setItem("p_long", cfg.long);
    localStorage.setItem("p_cycles", cfg.cycles);
    resetTimer();
    renderCycles();
    $("p-settings-panel").classList.remove("open");
    addLog("Config updated.");
  }

  function loadNotes() {
    el.notepad.value = localStorage.getItem("p_notes") || "";
    updateCharCount();
  }

  function saveNotes() {
    localStorage.setItem("p_notes", el.notepad.value);
  }

  function updateCharCount() {
    el.charCount.textContent = `${el.notepad.value.length} chars`;
  }

  function beep(freq, dur) {
    if (!state.audioCtx)
      state.audioCtx = new (window.AudioContext ||
        window.webkitAudioContext)();
    const osc = state.audioCtx.createOscillator();
    const gain = state.audioCtx.createGain();
    osc.connect(gain);
    gain.connect(state.audioCtx.destination);
    osc.frequency.value = freq;
    gain.gain.setValueAtTime(0.1, state.audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(
      0.01,
      state.audioCtx.currentTime + dur
    );
    osc.start();
    osc.stop(state.audioCtx.currentTime + dur);
  }

  function setupDraggable() {
    let pos1 = 0,
      pos2 = 0,
      pos3 = 0,
      pos4 = 0;
    el.float.onmousedown = dragMouseDown;

    function dragMouseDown(e) {
      e.preventDefault();
      pos3 = e.clientX;
      pos4 = e.clientY;
      document.onmouseup = closeDragElement;
      document.onmousemove = elementDrag;
    }

    function elementDrag(e) {
      e.preventDefault();
      pos1 = pos3 - e.clientX;
      pos2 = pos4 - e.clientY;
      pos3 = e.clientX;
      pos4 = e.clientY;
      el.float.style.top = el.float.offsetTop - pos2 + "px";
      el.float.style.left = el.float.offsetLeft - pos1 + "px";
      el.float.style.bottom = "auto";
      el.float.style.right = "auto";
    }

    function closeDragElement() {
      document.onmouseup = null;
      document.onmousemove = null;
    }
  }

  init();
})();
