// ── Tab badge (unseen alerts) ────────────────────────────────────────
let _unseenAlerts = 0;
const _baseTitle = document.title;
function updateTabBadge(delta) {
  _unseenAlerts = Math.max(0, _unseenAlerts + delta);
  if (_unseenAlerts > 0) {
    document.title = '(' + _unseenAlerts + ') ' + _baseTitle;
  } else {
    document.title = _baseTitle;
  }
}
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState === 'visible') {
    _unseenAlerts = 0;
    document.title = _baseTitle;
  }
});


// ── Real-time connection state (audit 5.12) ──────────────────────────
// The header already toggles between LIVE and reconnecting based on
// the SSE handshake. The audit asks for richer signal: how long since
// the last event, and a hard-fail badge when the agent has been
// silent for several minutes. We track the timestamp of the last
// observed SSE message in `window._lastSSEEventTs` (any kind of
// event counts as a heartbeat for connection-liveness purposes) and
// a 5 s ticker repaints the header.
var CONN_AMBER_AFTER_SECS = 60;     // amber "stalling" cue
var CONN_RED_AFTER_SECS   = 300;    // hard-fail "silent" cue
var _connStateMode = 'unknown';     // 'live' | 'reconnecting' | 'unknown'

function _markSseEvent() {
  window._lastSSEEventTs = Date.now();
  _renderConnectionStatus();
}

function _setConnState(mode) {
  _connStateMode = mode;
  _renderConnectionStatus();
}

function _renderConnectionStatus() {
  var el = document.getElementById('refreshStatus');
  if (!el) return;
  var lastTs = window._lastSSEEventTs;
  var nowMs = Date.now();
  var ageSecs = lastTs ? Math.max(0, Math.floor((nowMs - lastTs) / 1000)) : null;

  var color, label, ageHtml = '';
  if (_connStateMode === 'reconnecting') {
    color = '#888';
    label = 'reconnecting';
  } else if (ageSecs == null) {
    color = '#78e5ff';
    label = 'LIVE';
  } else if (ageSecs >= CONN_RED_AFTER_SECS) {
    color = '#f43f5e';
    label = 'NO DATA';
  } else if (ageSecs >= CONN_AMBER_AFTER_SECS) {
    color = '#f59e0b';
    label = 'STALLING';
  } else {
    color = '#78e5ff';
    label = 'LIVE';
  }

  if (ageSecs != null) {
    var ageText;
    if (ageSecs < 60) ageText = ageSecs + 's';
    else if (ageSecs < 3600) ageText = Math.floor(ageSecs / 60) + 'm';
    else ageText = Math.floor(ageSecs / 3600) + 'h';
    ageHtml = '<span style="color:var(--muted);font-size:0.65rem;margin-left:6px">last event ' + ageText + ' ago</span>';
  }

  el.innerHTML = '<span style="color:' + color + ';font-size:0.75rem;font-weight:600" title="Real-time connection state">● ' + label + '</span>' + ageHtml;
}

// Background ticker repaints the header every 5 s so the operator
// sees the age tick over and the colour flip on schedule even when
// no new events arrive.
setInterval(_renderConnectionStatus, 5000);

// 2026-05-15 slim-down: removed search-threats input + the dynamic
// search-count / no-results markers. Function kept as a defensive
// no-op so threats.js call sites continue to function (the search
// input no longer exists, so there's nothing to filter on).
function applyEntitySearch() { /* removed with the search box */ }

// ══════════════════════════════════════════════════════════════════════
// INIT — runs after all modules are loaded
// ══════════════════════════════════════════════════════════════════════

// Hydrate filter from URL. 2026-05-15 slim-down: Cases sidebar keeps
// only a single date picker — the compare-date, severity, detector,
// window, status and search inputs were all removed.
hydrateStateFromQuery();
var fltDateEl = document.getElementById('flt-date');
if (fltDateEl) fltDateEl.value = state.filters.date || today;
updatePivotUi();
loadActionConfig();
loadReportDates();

// Default view
showView('home');

// Keyboard shortcuts
document.addEventListener('keydown', (ev) => {
  if (ev.key === 'Escape') closeActionModal();
});

// Cap the date picker at today so future dates grey out in the
// calendar widget. `syncFiltersFromUi` adds the matching guard
// against typed-in future dates.
(function capDatePickerAtToday() {
  var todayStr = new Date().toISOString().slice(0, 10);
  var el = document.getElementById('flt-date');
  if (el) el.max = todayStr;
})();

// Filter event listener (date is the only knob now).
var fltDateChangeEl = document.getElementById('flt-date');
if (fltDateChangeEl) {
  fltDateChangeEl.addEventListener('change', () => refreshLeft(true));
}

// Initial data load — route first, then load data for visible view
initRouter();
refreshLeft(false).then(() => {
  if (state.selected.value) {
    loadJourney(state.selected.type, state.selected.value);
  }
});

// ── SSE live connection ──────────────────────────────────────────────
(function startSse() {
  let fallbackTimer = null;
  let reconnectTimer = null;

  function armFallback() {
    clearTimeout(fallbackTimer);
    fallbackTimer = setTimeout(() => {
      refreshLeftLive();
      _refreshActiveView();
      fallbackTimer = setInterval(() => {
        refreshLeftLive();
        _refreshActiveView();
      }, 30000);
    }, 35000);
  }

  // 2026-05-15: the Sensors view was deleted; its content folded into
  // Home (`#homeSensorsPanel`). The Home refresh path below already
  // re-fetches `/api/sensors`, so this helper has no remaining active
  // surfaces. Kept as an extension point — if a future view starts
  // freezing on SSE drop, add the refresh call here.
  function _refreshActiveView() {
    // intentionally empty — see comment above
  }

  function connect() {
    clearTimeout(reconnectTimer);
    fetch('/api/events/stream', { headers: { 'Accept': 'text/event-stream' } })
      .then(res => {
        if (!res.ok || !res.body) throw new Error('SSE connect failed');
        clearTimeout(fallbackTimer);
        clearInterval(fallbackTimer);
        _setConnState('live');
        _markSseEvent();
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        let lastEvent = '';
        function pump() {
          reader.read().then(({ done, value }) => {
            if (done) { scheduleReconnect(); return; }
            buf += dec.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop();
            for (const line of lines) {
              if (line.startsWith('event: ')) {
                lastEvent = line.slice(7).trim();
              } else if (line.startsWith('data: ')) {
                _markSseEvent();
                if (lastEvent === 'refresh') {
                  // Throttle: at most 1 refresh per 5 seconds to avoid 429s
                  var now = Date.now();
                  if (!window._lastSSERefresh || now - window._lastSSERefresh > 5000) {
                    window._lastSSERefresh = now;
                    refreshLeftLive();
                    if (document.getElementById('viewHome').style.display !== 'none') loadHome();
                    // 2026-05-15: the Sensors view + its loadSensors
                    // entrypoint were deleted. Home's `renderHomeSensorsPanel`
                    // now drives the per-collector breakdown and the
                    // Event Timeline off the same /api/sensors payload
                    // `loadHome` already fetches above.
                  }
                }
                lastEvent = '';
              }
            }
            pump();
          }).catch(() => scheduleReconnect());
        }
        pump();
      })
      .catch(() => scheduleReconnect());
  }

  function scheduleReconnect() {
    _setConnState('reconnecting');
    armFallback();
    reconnectTimer = setTimeout(connect, 3000);
  }

  armFallback();
  connect();
})();
