// ── Honeypot tab ──────────────────────────────────────────────────────
async function loadHoneypot() {
  const status = document.getElementById('honeypotViewStatus');
  const content = document.getElementById('honeypotContent');
  if (!status || !content) return;
  status.textContent = 'Loading…';
  content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
  try {
    const data = await loadJson('/api/honeypot/sessions');
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

// Audit 2.9: tell engaged sessions apart from listener-only ones.
// "Engaged" = the attacker actually typed something or tried to log
// in. The bug surface was a wall of 178 sessions with 0 commands /
// 0 auth attempts, which read like "honeypot is busy" but actually
// meant "honeypot collected nothing".
function _honeypotIsEngaged(s) {
  return ((s && s.commands_count) || 0) > 0 ||
         ((s && s.auth_attempts) || 0) > 0;
}

var _honeypotShowEngagedOnly = false;

function toggleHoneypotEngagedFilter() {
  _honeypotShowEngagedOnly = !_honeypotShowEngagedOnly;
  loadHoneypot();
}

function renderHoneypot(data) {
  const allSessions = data.sessions || [];
  const engagedCount = allSessions.filter(_honeypotIsEngaged).length;
  const unengagedCount = allSessions.length - engagedCount;
  const sessions = _honeypotShowEngagedOnly
    ? allSessions.filter(_honeypotIsEngaged)
    : allSessions;

  // Test button shown regardless of whether sessions exist
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

  // Audit 2.9: explanatory banner with engaged-vs-unengaged split
  // and a filter toggle. Only renders when there is at least one
  // session — empty state has its own copy below.
  let engagementBanner = '';
  if (allSessions.length > 0) {
    const filterLabel = _honeypotShowEngagedOnly
      ? 'Show all sessions'
      : 'Show only engaged sessions';
    const engagedPctText = allSessions.length > 0
      ? Math.round((engagedCount / allSessions.length) * 100) + '%'
      : '0%';
    engagementBanner = '<div id="honeypotEngagementBanner" style="padding:14px 16px;max-width:900px;margin:12px auto 0;border:1px dashed var(--line);border-radius:10px;background:rgba(120,229,255,0.04)">' +
      '<div style="font-size:0.78rem;color:var(--text);font-weight:600;margin-bottom:6px">' +
      'Honeypot engagement: ' + esc(engagedCount) + ' engaged · ' + esc(unengagedCount) + ' unengaged · ' + esc(engagedPctText) + ' engagement rate' +
      '</div>' +
      '<div style="font-size:0.7rem;color:var(--muted);line-height:1.5;margin-bottom:8px">' +
      'Engaged = attacker typed at least one command or sent an authentication attempt. ' +
      'Unengaged = a listener was hit (port scan, banner grab) but the attacker walked away ' +
      'before the fake shell exchange. Unengaged sessions still confirm the honeypot listener is alive.' +
      '</div>' +
      '<button type="button" id="honeypotEngagedFilterBtn" onclick="toggleHoneypotEngagedFilter()" ' +
      'style="background:transparent;border:1px solid var(--accent);color:var(--accent);' +
      'border-radius:8px;font-size:0.7rem;font-weight:600;padding:5px 12px;cursor:pointer">' +
      esc(filterLabel) + '</button>' +
      '</div>';
  }

  if (sessions.length === 0) {
    if (allSessions.length === 0) {
      return testBtn + '<div class="empty" style="padding:40px;text-align:center;opacity:0.5">' + lucideIcon('bug',{size:18}) + ' No honeypot sessions yet.<br><span style="font-size:0.8rem">Sessions appear here when attackers interact with a honeypot listener.</span></div>';
    }
    // Filter is on but no engaged sessions. Tell the operator why
    // the list looks empty under the filter — different empty-state
    // from "agent never recorded anything".
    return testBtn + engagementBanner +
      '<div class="empty" style="padding:40px;text-align:center;opacity:0.6">' +
      lucideIcon('bug',{size:18}) +
      ' No engaged sessions in this dataset.<br>' +
      '<span style="font-size:0.8rem">' + esc(allSessions.length) +
      ' listener-only session' + (allSessions.length === 1 ? '' : 's') +
      ' recorded; none progressed to commands or auth attempts.</span>' +
      '</div>';
  }

  let html = testBtn + engagementBanner + '<div style="padding:16px;max-width:900px;margin:0 auto">';
  const titleSuffix = _honeypotShowEngagedOnly
    ? ' (' + sessions.length + ' engaged of ' + allSessions.length + ' total)'
    : ' (' + sessions.length + ')';
  html += '<div style="font-size:1.1rem;font-weight:600;color:var(--accent);margin-bottom:16px;display:flex;align-items:center;gap:8px">' + lucideIcon('bug',{size:18}) + ' Honeypot Sessions' + titleSuffix + '</div>';

  for (const s of sessions) {
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

    html += '<div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:16px;margin-bottom:12px">';

    // Header row
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">';
    html += '<span style="font-family:monospace;font-size:1rem;color:var(--accent)">' + esc(ip) + '</span>';
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

    // Session ID
    html += '<div style="font-size:0.7rem;opacity:0.4;margin-bottom:10px;font-family:monospace">' + esc(sessionId) + '</div>';

    // Commands
    if (commands.length > 0) {
      html += '<div style="margin-bottom:10px">';
      html += '<div style="font-size:0.75rem;font-weight:600;color:rgba(255,255,255,0.7);margin-bottom:6px">Commands typed by attacker</div>';
      html += '<div style="background:rgba(0,0,0,0.3);border-radius:6px;padding:10px;font-family:monospace;font-size:0.78rem;color:rgba(255,255,255,0.85)">';
      for (const cmd of commands.slice(0, 15)) {
        html += '<div style="margin-bottom:3px"><span style="color:var(--accent);opacity:0.7">$</span> ' + esc(cmd) + '</div>';
      }
      if (commands.length > 15) {
        html += '<div style="opacity:0.4;font-size:0.7rem">... ' + (commands.length - 15) + ' more commands</div>';
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
  }

  html += '</div>';
  return html;
}

