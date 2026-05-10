// ── Honeypot tab ──────────────────────────────────────────────────────
//
// Spec 046 Phase A — paginated, engaged-only by default. The previous
// implementation fetched the entire session list (244+ rows in prod)
// and filtered client-side; the wall of unengaged sessions read like
// "honeypot is busy" but meant "honeypot collected nothing". This
// version asks the backend for the engaged-only first page and lets
// the operator toggle / paginate when they want everything.

// Pagination + filter state (kept module-scoped so the UI buttons can
// mutate it before triggering a refetch).
var _honeypotPage = 0;
var _honeypotPageSize = 20;
var _honeypotShowEngagedOnly = true;  // Spec 046 Inv. 7 — default
var _honeypotExpandedSessions = new Set();

async function loadHoneypot() {
  const status = document.getElementById('honeypotViewStatus');
  const content = document.getElementById('honeypotContent');
  if (!status || !content) return;
  status.textContent = 'Loading…';
  content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
  try {
    const params = new URLSearchParams({
      page: String(_honeypotPage),
      size: String(_honeypotPageSize),
      engaged_only: String(_honeypotShowEngagedOnly),
    });
    const data = await loadJson('/api/honeypot/sessions?' + params.toString());
    status.textContent = 'Updated ' + new Date().toLocaleTimeString();
    content.innerHTML = renderHoneypot(data);
  } catch(e) {
    status.textContent = 'Error';
    content.innerHTML = '<div class="empty" style="padding:40px;text-align:center;color:var(--danger)">Failed to load honeypot sessions.</div>';
  }
}

async function testHoneypot() {
  const btn = document.getElementById('btnTestHoneypot');
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = '⏳ Starting...';
  try {
    const reason = 'Teste manual via dashboard';
    const resp = await fetch('/api/action/honeypot', {
      method: 'POST',
      // x-requested-with required by CSRF middleware (audit I-14).
      headers: {
        'Content-Type': 'application/json',
        'x-requested-with': 'XMLHttpRequest',
      },
      body: JSON.stringify({ reason, duration_secs: 120 }),
      credentials: 'include',
    });
    const data = await resp.json();
    if (data.success) {
      showToast(lucideIcon('bug',{size:14}) + ' ' + data.message, 'ok');
    } else {
      showToast(lucideIcon('x-circle',{size:14}) + ' ' + data.message, 'err');
    }
  } catch (e) {
    showToast(lucideIcon('x-circle',{size:14}) + ' Request failed: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
    btn.innerHTML = lucideIcon('flask-conical',{size:14}) + ' <span style="margin-left:6px">Start test session</span>';
  }
}

// Mirrors the Rust-side `session_is_engaged` predicate. Kept for the
// per-card "ENGAGED" badge rendering.
function _honeypotIsEngaged(s) {
  return ((s && s.commands_count) || 0) > 0 ||
         ((s && s.auth_attempts) || 0) > 0;
}

function toggleHoneypotEngagedFilter() {
  _honeypotShowEngagedOnly = !_honeypotShowEngagedOnly;
  _honeypotPage = 0;  // Reset to first page when filter changes.
  loadHoneypot();
}

function honeypotPrevPage() {
  if (_honeypotPage > 0) {
    _honeypotPage -= 1;
    loadHoneypot();
  }
}

function honeypotNextPage() {
  _honeypotPage += 1;
  loadHoneypot();
}

function honeypotToggleSession(sessionId) {
  if (_honeypotExpandedSessions.has(sessionId)) {
    _honeypotExpandedSessions.delete(sessionId);
  } else {
    _honeypotExpandedSessions.add(sessionId);
  }
  loadHoneypot();
}

// Spec 046 Inv. 8 — three distinct empty states. Centralised here so
// the render switch below is shorter and the anchor test
// (`honeypot_js_handles_three_empty_states`) can grep for the helper
// name and the three branches.
function _honeypotEmptyState(data) {
  const total = data.total || 0;
  const totalEngaged = data.total_engaged || 0;
  const engagedOnly = data.engaged_only !== false;

  // Case (a): listener has no data at all.
  if (total === 0) {
    return '<div class="empty" style="padding:40px;text-align:center;opacity:0.5">' +
      lucideIcon('bug',{size:18}) +
      ' Honeypot listener active — no probes yet.<br>' +
      '<span style="font-size:0.8rem">Sessions appear here when attackers reach the listener. ' +
      'On a public IP this typically takes minutes; on an internal IP it may take days.</span>' +
      '</div>';
  }

  // Case (b): there is data but ZERO engaged sessions overall — the
  // honeypot is healthy but no attacker has progressed past the
  // banner-grab phase yet. This is the "wow surface hasn't fired"
  // state.
  if (totalEngaged === 0 && engagedOnly) {
    return '<div class="empty" style="padding:40px;text-align:center;opacity:0.6">' +
      lucideIcon('shield',{size:18}) +
      ' Listener confirmed alive — ' + esc(total) + ' probe' + (total === 1 ? '' : 's') + ' detected, no shell engagements yet.<br>' +
      '<span style="font-size:0.8rem">Spec 046 tiered acceptance is selecting against single-shot scanners. ' +
      'A multi-attempt dropper hitting a known-weak credential will surface here.</span>' +
      '</div>';
  }

  // Case (c): filter is on, current page is empty, but other pages
  // have engaged sessions (or filter could be flipped to reveal
  // unengaged sessions).
  return '<div class="empty" style="padding:40px;text-align:center;opacity:0.6">' +
    lucideIcon('bug',{size:18}) +
    ' Page ' + esc(_honeypotPage + 1) + ' is empty under the current filter.<br>' +
    '<span style="font-size:0.8rem">Use the controls above to go back to page 1, ' +
    'or toggle "Show all sessions" to include unengaged probes.</span>' +
    '</div>';
}

// CodeRabbit PR #508 review: the pagination bar is rendered both above
// and below the cards. Using a hardcoded `id` would produce duplicate
// IDs in the DOM (invalid HTML, breaks selector-based behaviour). The
// `position` argument scopes the id (`top`/`bottom`) so each instance
// is uniquely addressable.
function _honeypotPaginationBar(data, position) {
  const filteredTotal = data.filtered_total || 0;
  const size = data.size || _honeypotPageSize;
  const page = data.page || 0;
  const hasMore = !!data.has_more;
  const startIdx = page * size + 1;
  const endIdx = Math.min((page + 1) * size, filteredTotal);
  const range = filteredTotal === 0
    ? '0'
    : startIdx + '–' + endIdx + ' of ' + filteredTotal;

  const prevDisabled = page === 0 ? 'disabled' : '';
  const nextDisabled = !hasMore ? 'disabled' : '';
  const buttonStyle = (disabled) =>
    'background:transparent;border:1px solid var(--line);color:var(--text);' +
    'border-radius:6px;font-size:0.7rem;padding:4px 12px;cursor:' +
    (disabled ? 'not-allowed;opacity:0.4' : 'pointer') + ';font-family:inherit';

  return '<div id="honeypotPagination-' + esc(position) + '" style="display:flex;align-items:center;gap:10px;padding:10px 16px 0;max-width:900px;margin:0 auto;font-size:0.75rem;color:var(--muted)">' +
    '<button type="button" onclick="honeypotPrevPage()" ' + prevDisabled +
    ' style="' + buttonStyle(page === 0) + '">Prev</button>' +
    '<span>' + esc(range) + '</span>' +
    '<button type="button" onclick="honeypotNextPage()" ' + nextDisabled +
    ' style="' + buttonStyle(!hasMore) + '">Next</button>' +
    '</div>';
}

function _honeypotSessionCard(s) {
  const ip = s.target_ip || '-';
  const sessionId = s.session_id || '-';
  const startedAt = s.started_at ? new Date(s.started_at).toLocaleString() : '-';
  const duration = s.duration_secs ? s.duration_secs + 's' : '-';
  const cmdCount = s.commands_count || 0;
  const authCount = s.auth_attempts || 0;
  const commands = s.commands || [];
  const iocs = s.iocs || [];
  const blocked = !!s.blocked;
  const mode = s.mode || 'listener';
  const engaged = _honeypotIsEngaged(s);
  const expanded = _honeypotExpandedSessions.has(sessionId);

  let html = '<div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:16px;margin-bottom:12px">';

  // Header row
  html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">';
  html += '<span style="font-family:monospace;font-size:1rem;color:var(--accent)">' + esc(ip) + '</span>';
  if (engaged) {
    html += '<span style="background:rgba(245,158,11,0.15);color:#f59e0b;border:1px solid rgba(245,158,11,0.3);border-radius:4px;padding:2px 8px;font-size:0.7rem;font-weight:600">ENGAGED</span>';
  }
  if (blocked) {
    html += '<span style="background:rgba(58,194,126,0.15);color:#3ac27e;border:1px solid rgba(58,194,126,0.3);border-radius:4px;padding:2px 8px;font-size:0.7rem;font-weight:600">BLOCKED</span>';
  }
  if (mode === 'always_on') {
    html += '<span style="background:rgba(120,229,255,0.08);color:var(--accent);border:1px solid rgba(120,229,255,0.2);border-radius:4px;padding:2px 8px;font-size:0.7rem">ALWAYS-ON</span>';
  }
  html += '<span style="font-size:0.75rem;opacity:0.6">' + esc(startedAt) + '</span>';
  if (s.duration_secs) html += '<span style="font-size:0.75rem;opacity:0.6">Duration: ' + esc(duration) + '</span>';
  html += '<span style="font-size:0.75rem;opacity:0.6">Auth attempts: ' + authCount + '</span>';
  html += '<span style="font-size:0.75rem;opacity:0.6">Commands: ' + cmdCount + '</span>';
  html += '</div>';

  // Session ID + expand toggle
  html += '<div style="display:flex;justify-content:space-between;align-items:center;font-size:0.7rem;opacity:0.5;margin-bottom:10px">';
  html += '<span style="font-family:monospace">' + esc(sessionId) + '</span>';
  if (engaged) {
    html += '<button type="button" onclick="honeypotToggleSession(\'' + esc(sessionId) + '\')" ' +
      'style="background:transparent;border:1px solid var(--line);color:var(--accent);' +
      'border-radius:6px;font-size:0.7rem;padding:3px 10px;cursor:pointer;font-family:inherit">' +
      (expanded ? 'Collapse' : 'Expand transcript') + '</button>';
  }
  html += '</div>';

  // Commands - always show first up to 15 even when collapsed.
  if (commands.length > 0) {
    const visibleLimit = expanded ? commands.length : 15;
    html += '<div style="margin-bottom:10px">';
    html += '<div style="font-size:0.75rem;font-weight:600;color:rgba(255,255,255,0.7);margin-bottom:6px">Commands typed by attacker</div>';
    html += '<div style="background:rgba(0,0,0,0.3);border-radius:6px;padding:10px;font-family:monospace;font-size:0.78rem;color:rgba(255,255,255,0.85)">';
    for (const cmd of commands.slice(0, visibleLimit)) {
      html += '<div style="margin-bottom:3px"><span style="color:var(--accent);opacity:0.7">$</span> ' + esc(cmd) + '</div>';
    }
    if (!expanded && commands.length > visibleLimit) {
      html += '<div style="opacity:0.4;font-size:0.7rem">… ' + (commands.length - visibleLimit) + ' more (expand transcript to see)</div>';
    }
    html += '</div></div>';
  }

  // IOCs
  if (iocs.length > 0) {
    html += '<div style="margin-top:10px">';
    html += '<div style="font-size:0.75rem;font-weight:600;color:#f59e0b;margin-bottom:6px;display:flex;align-items:center;gap:6px">' + lucideIcon('alert-triangle',{size:12}) + ' Extracted IOCs</div>';
    html += '<div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:10px">';
    for (const ioc of iocs) {
      html += '<div style="font-family:monospace;font-size:0.78rem;color:var(--warn);margin-bottom:3px">' + esc(ioc) + '</div>';
    }
    html += '</div></div>';
  }

  html += '</div>'; // end session card
  return html;
}

function renderHoneypot(data) {
  const sessions = data.sessions || [];
  const total = data.total || 0;
  const totalEngaged = data.total_engaged || 0;
  const totalUnengaged = data.total_unengaged || 0;
  const filteredTotal = data.filtered_total || 0;
  const engagedOnly = data.engaged_only !== false;

  // Test button always visible.
  const testBtn = '<div style="padding:16px 16px 0;max-width:900px;margin:0 auto">' +
    '<button id="btnTestHoneypot" onclick="testHoneypot()" ' +
    'style="background:rgba(120,229,255,0.08);border:1px solid rgba(120,229,255,0.28);' +
    'border-radius:8px;color:var(--accent);font-size:0.78rem;font-weight:600;' +
    'padding:8px 18px;cursor:pointer;transition:background 0.15s,border-color 0.15s;' +
    'font-family:inherit" ' +
    'onmouseover="this.style.background=\'rgba(120,229,255,0.15)\'" ' +
    'onmouseout="this.style.background=\'rgba(120,229,255,0.08)\'">' +
    lucideIcon('flask-conical',{size:14}) + ' <span style="margin-left:6px">Start test session</span></button>' +
    '<span style="font-size:0.68rem;color:var(--muted);margin-left:10px">' +
    'Injects a test incident - the agent evaluates and triggers the honeypot on the next tick (≤2 s).' +
    '</span></div>';

  // Engagement banner — always renders when there is ANY data so the
  // operator sees the engaged/unengaged split even when the engaged-
  // only filter hides the cards.
  let engagementBanner = '';
  if (total > 0) {
    const filterLabel = engagedOnly
      ? 'Show all sessions (' + esc(totalUnengaged) + ' unengaged hidden)'
      : 'Show only engaged sessions';
    // CodeQL flagged the prior `total > 0 ? ... : '0%'` ternary as a
    // useless comparison — this entire block is already inside
    // `if (total > 0)`, so the guard is redundant.
    const engagedPctText = Math.round((totalEngaged / total) * 100) + '%';
    engagementBanner = '<div id="honeypotEngagementBanner" style="padding:14px 16px;max-width:900px;margin:12px auto 0;border:1px dashed var(--line);border-radius:10px;background:rgba(120,229,255,0.04)">' +
      '<div style="font-size:0.78rem;color:var(--text);font-weight:600;margin-bottom:6px">' +
      'Honeypot engagement: ' + esc(totalEngaged) + ' engaged · ' + esc(totalUnengaged) + ' unengaged · ' + esc(engagedPctText) + ' engagement rate' +
      '</div>' +
      '<div style="font-size:0.7rem;color:var(--muted);line-height:1.5;margin-bottom:8px">' +
      'Engaged = attacker typed at least one command or sent an authentication attempt. ' +
      'Unengaged = a listener was hit (port scan, banner grab) but the attacker walked away ' +
      'before the fake shell exchange. Spec 046 tiered acceptance now rejects single-shot ' +
      'scanners on attempt #1 and only opens the shell when a Mirai-class dropper hits a ' +
      'known-weak credential after multiple attempts.' +
      '</div>' +
      '<button type="button" id="honeypotEngagedFilterBtn" onclick="toggleHoneypotEngagedFilter()" ' +
      'style="background:transparent;border:1px solid var(--accent);color:var(--accent);' +
      'border-radius:8px;font-size:0.7rem;font-weight:600;padding:5px 12px;cursor:pointer">' +
      esc(filterLabel) + '</button>' +
      '</div>';
  }

  // Three empty states (Spec 046 Inv. 8). Routed through helper.
  if (sessions.length === 0) {
    return testBtn + engagementBanner + _honeypotEmptyState(data);
  }

  // Render the page header + pagination + cards.
  let html = testBtn + engagementBanner + _honeypotPaginationBar(data, 'top');
  html += '<div style="padding:16px;max-width:900px;margin:0 auto">';
  const titleSuffix = engagedOnly
    ? ' (' + sessions.length + ' on this page · ' + filteredTotal + ' engaged total)'
    : ' (' + sessions.length + ' on this page · ' + filteredTotal + ' total)';
  html += '<div style="font-size:1.1rem;font-weight:600;color:var(--accent);margin-bottom:16px;display:flex;align-items:center;gap:8px">' +
    lucideIcon('bug',{size:18}) + ' Honeypot Sessions' + titleSuffix + '</div>';

  for (const s of sessions) {
    html += _honeypotSessionCard(s);
  }

  html += '</div>';
  html += _honeypotPaginationBar(data, 'bottom');  // Bottom bar mirrors the top.
  return html;
}
