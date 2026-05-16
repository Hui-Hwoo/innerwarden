// ── Intelligence tab ──────────────────────────────────────────────
// 2026-05-03 (PR #413): the Playbooks Intel sub-tab + probe were
// removed alongside the playbook engine. Future declarative
// orchestration belongs to Spec 042 active defense.

// 2026-05-15: page size + active risk filter persisted across calls.
// Operator-reported: KPI "High Risk: 100" was the same as the visible
// row count, not the real bucket size; "Total: 4141" had no way to
// reach the other 4041; sorted-desc table gave no visual cue for
// where the risk cliff was.
const INTEL_PAGE_SIZE = 100;
let _intelOffset = 0;
let _intelRiskFilter = 0; // 0 = all, 70 = high, 40 = medium+, ...
let _intelLoadedProfiles = []; // accumulator for "Load more"

async function loadIntel() {
  _intelOffset = 0;
  _intelLoadedProfiles = [];
  await fetchAndRenderIntel(/* append= */ false);
}

async function fetchAndRenderIntel(append) {
  const status = document.getElementById('intelViewStatus');
  const content = document.getElementById('intelContent');
  if (status) status.textContent = append ? 'Loading more…' : 'Loading…';
  const signal = window._activeFetch_intel ? window._activeFetch_intel.signal : undefined;
  try {
    // 2026-05-16 PR-E: Intel UX slim — operator: "tinha que deixar
    // isso mais simples e organizado". Removed the 4 KPI tiles
    // (Total Profiles / High Risk / Medium / Countries — none of
    // them were actionable; "Total: 4141" was noise, "Countries"
    // was trivia), the Sort dropdown (default risk_score desc is
    // what every operator actually wants), and the Min Risk input
    // (replaced by 3 explicit chips with active state). The result
    // is one search box + three chips above the risk-sorted table.
    // No 300 filtros e tralha.
    const url = '/api/attacker-profiles?sort=risk_score'
      + '&min_risk=' + _intelRiskFilter
      + '&limit=' + INTEL_PAGE_SIZE
      + '&offset=' + _intelOffset;
    const data = await loadJson(url, { signal });
    if (!data || !data.profiles) { content.innerHTML = '<p style="color:var(--dim)">No attacker profiles yet.</p>'; return; }

    if (append) {
      _intelLoadedProfiles = _intelLoadedProfiles.concat(data.profiles);
    } else {
      _intelLoadedProfiles = data.profiles.slice();
    }

    const totalAll = data.total || 0;

    // Filter row — IP search (left) + 3 risk chips (right). One
    // line, no clutter. The active chip carries the accent ring so
    // the operator always sees which slice the table reflects.
    const chip = function (label, filterValue) {
      const active = _intelRiskFilter === filterValue;
      const cls = active ? 'intel-chip intel-chip-active' : 'intel-chip';
      return '<button type="button" class="' + cls + '" onclick="setIntelRiskFilter(' + filterValue + ')">' + label + '</button>';
    };
    let html = '<div class="intel-toolbar">'
      + '<input id="intelIpSearch" type="search" placeholder="search IP…" oninput="filterIntelByIp(this.value)" autocomplete="off" spellcheck="false" class="intel-search" />'
      + '<div class="intel-chip-group" role="group" aria-label="Risk filter">'
      + chip('All', 0)
      + chip('≥40 (Medium+)', 40)
      + chip('≥70 (High)', 70)
      + '</div>'
      + '</div>';

    html += '<table id="intelTable" style="width:100%;border-collapse:collapse;font-size:0.85rem;">'
      + '<thead><tr style="border-bottom:2px solid var(--border);text-align:left;">'
      + '<th style="padding:6px;">Risk</th><th style="padding:6px;">IP</th><th style="padding:6px;">Country</th>'
      + '<th style="padding:6px;">Incidents</th><th style="padding:6px;">Blocks</th><th style="padding:6px;">Detectors</th>'
      + '<th style="padding:6px;">Pattern</th><th style="padding:6px;">Last Seen</th>'
      + '</tr></thead><tbody>';

    for (const p of _intelLoadedProfiles) {
      const riskColor = p.risk_score >= 70 ? '#e74c3c' : p.risk_score >= 40 ? '#f39c12' : '#27ae60';
      const riskBar = '<div style="display:flex;align-items:center;gap:6px;">'
        + '<div style="width:40px;height:8px;background:var(--border);border-radius:4px;overflow:hidden;">'
        + '<div style="width:' + p.risk_score + '%;height:100%;background:' + riskColor + ';"></div></div>'
        + '<span style="color:' + riskColor + ';font-weight:600;">' + p.risk_score + '</span></div>';
      const country = p.geo?.country_code || '??';
      const detectors = (p.detectors_triggered || []).slice(0, 3).join(', ');
      const patternRaw = p.dna?.pattern_class || 'unknown';
      const lastSeen = p.last_seen ? new Date(p.last_seen).toLocaleDateString() : '\u2014';
      const patternLabels = { regular_scanner:'Regular Scanner', targeted:'Targeted Attack', opportunistic:'Opportunistic', unknown:'Unknown' };
      const pattern = patternLabels[patternRaw] || patternRaw.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      const patternBadge = pattern === 'Regular Scanner' ? lucideIcon('refresh-ccw') : pattern === 'Targeted Attack' ? lucideIcon('target') : pattern === 'Opportunistic' ? lucideIcon('crosshair') : lucideIcon('alert-circle');
      // 2026-05-15 slim-down: dropped the DNA-hash column from the
      // table. The full DNA fingerprint is still on the per-profile
      // detail page; on the list, an 10-char monospace string was
      // chrome noise that pushed Last Seen into ellipsis territory
      // on common screen widths.
      // 2026-05-15: tint rows \u226570 so the operator can spot the cliff
      // even when the visible page mixes risk bands.
      const rowTint = p.risk_score >= 70 ? 'background:rgba(231,76,60,0.05);' : '';
      html += '<tr style="border-bottom:1px solid var(--border);cursor:pointer;' + rowTint + '" data-ip="' + esc(p.ip) + '" onclick="openProfileModal(\'' + esc(p.ip) + '\')">'
        + '<td style="padding:6px;">' + riskBar + '</td>'
        + '<td style="padding:6px;font-family:monospace;">' + esc(p.ip) + '</td>'
        + '<td style="padding:6px;">' + country + '</td>'
        + '<td style="padding:6px;">' + p.total_incidents + '</td>'
        + '<td style="padding:6px;">' + p.total_blocks + '</td>'
        + '<td style="padding:6px;font-size:0.75rem;">' + detectors + '</td>'
        + '<td style="padding:6px;">' + patternBadge + ' ' + pattern + '</td>'
        + '<td style="padding:6px;font-size:0.75rem;">' + lastSeen + '</td>'
        + '</tr>';
    }
    html += '</tbody></table>';

    // "Showing X of Y" + Load more button. Honest about pagination \u2014
    // operator no longer has to wonder where the other 4000+ profiles
    // went.
    const shown = _intelLoadedProfiles.length;
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px;font-size:0.78rem;color:var(--muted);">';
    html += '<span>Showing ' + shown + ' of ' + totalAll + ' profiles' + (_intelRiskFilter > 0 ? ' (filter: risk \u2265 ' + _intelRiskFilter + ')' : '') + '</span>';
    if (shown < totalAll) {
      html += '<button type="button" onclick="loadMoreIntelProfiles()" style="padding:5px 14px;border-radius:6px;border:1px solid var(--accent);background:transparent;color:var(--accent);cursor:pointer;font-weight:600;">Load more (' + Math.min(INTEL_PAGE_SIZE, totalAll - shown) + ' more)</button>';
    }
    html += '</div>';

    content.innerHTML = html;
    if (status) status.textContent = shown + ' of ' + totalAll + ' profiles';
  } catch(e) {
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    content.innerHTML = '<p style="color:#e74c3c;">Failed to load: ' + esc(e.message) + '</p>';
    if (status) status.textContent = 'Error';
  }
}

// 2026-05-15: click handlers \u2014 keep them at module scope so the
// `onclick=` attributes in the rendered HTML can reach them.
function setIntelRiskFilter(risk) {
  _intelRiskFilter = risk;
  loadIntel();
}

function loadMoreIntelProfiles() {
  _intelOffset += INTEL_PAGE_SIZE;
  fetchAndRenderIntel(/* append= */ true);
}

function filterIntelByIp(query) {
  const q = (query || '').trim().toLowerCase();
  const rows = document.querySelectorAll('#intelTable tbody tr');
  rows.forEach(function(r) {
    const ip = (r.getAttribute('data-ip') || '').toLowerCase();
    r.style.display = (!q || ip.indexOf(q) !== -1) ? '' : 'none';
  });
}

// 2026-05-15 PR-A: dossier body builder. Returns the HTML for an
// attacker dossier given the `/api/attacker-profiles/<ip>` payload.
// Header chrome (back button / close button) is the caller's
// responsibility — `openProfileModal` (the shared drill-down used by
// Cases journey + Intel profile rows) supplies its own X-close in the
// modal header, so this body is chrome-free.
function renderProfileDossierHtml(p) {
  if (!p || p.error) {
    return `<p style="color:#e74c3c">${p?.error || 'Not found'}</p>`;
  }
  const riskColor = p.risk_score >= 70 ? '#e74c3c' : p.risk_score >= 40 ? '#f39c12' : '#27ae60';
  let html = '';
  html += `<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">`;

    // Left: Identity + Timeline
    html += `<div class="kpi-card" style="padding:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('target',{size:18})} ${p.ip}</h3>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <div style="width:120px;height:12px;background:var(--border);border-radius:6px;overflow:hidden;">
          <div style="width:${p.risk_score}%;height:100%;background:${riskColor};"></div>
        </div>
        <span style="font-size:1.5rem;font-weight:700;color:${riskColor};">${p.risk_score}/100</span>
      </div>
      <table style="font-size:0.8rem;"><tbody>
        <tr><td style="padding:2px 8px;color:var(--dim);">Country</td><td>${p.geo?.country || '—'} (${p.geo?.country_code || '??'})</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">ISP</td><td>${p.geo?.isp || '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">ASN</td><td>${p.geo?.asn || '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">AbuseIPDB</td><td>${p.abuseipdb_score ?? '—'}/100</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">CrowdSec</td><td>${p.crowdsec_listed ? lucideIcon('alert-triangle',{size:12}) + ' Listed' : lucideIcon('check-circle',{size:12}) + ' Clean'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Tor</td><td>${p.is_tor ? lucideIcon('globe',{size:12}) + ' Yes' : 'No'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">First Seen</td><td>${p.first_seen ? new Date(p.first_seen).toLocaleString() : '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Last Seen</td><td>${p.last_seen ? new Date(p.last_seen).toLocaleString() : '—'}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Days Active</td><td>${p.visit_count} days</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Pattern</td><td>${p.dna?.pattern_class || 'unknown'}</td></tr>
      </tbody></table>
    </div>`;

    // Right: Attack Profile
    html += `<div class="kpi-card" style="padding:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('swords',{size:16})} Attack Profile</h3>
      <table style="font-size:0.8rem;"><tbody>
        <tr><td style="padding:2px 8px;color:var(--dim);">Incidents</td><td>${p.total_incidents}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Blocks</td><td>${p.total_blocks}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Shield Blocks</td><td>${p.shield_blocks || 0}${p.shield_last_blocked ? ' (last: ' + new Date(p.shield_last_blocked).toLocaleString() + ')' : ''}</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Honeypot</td><td>${p.total_honeypot_diversions} diversions, ${p.honeypot_sessions} sessions</td></tr>
        <tr><td style="padding:2px 8px;color:var(--dim);">Max Severity</td><td style="font-weight:600;">${p.max_severity}</td></tr>
      </tbody></table>
      <h4 style="margin:12px 0 4px;font-size:0.8rem;color:var(--dim);">Detectors Triggered</h4>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">${(p.detectors_triggered||[]).map(d=>`<span style="padding:2px 6px;border-radius:4px;background:var(--border);font-size:0.7rem;">${esc(d)}</span>`).join('')}</div>
      <h4 style="margin:12px 0 4px;font-size:0.8rem;color:var(--dim);">MITRE Techniques</h4>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">${(p.mitre_techniques||[]).map(t=>`<span style="padding:2px 6px;border-radius:4px;background:#2c1810;color:#f39c12;font-size:0.7rem;">${esc(t)}</span>`).join('')}</div>
    </div>`;
    html += `</div>`;

    // DNA section
    html += `<div class="kpi-card" style="padding:16px;margin-top:16px;">
      <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('dna',{size:16})} Behavioral DNA</h3>
      <div style="font-family:monospace;font-size:0.75rem;color:var(--dim);margin-bottom:8px;">Hash: ${p.dna?.hash || '—'}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;">
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Hour Distribution</h4>
          <div style="display:flex;align-items:flex-end;gap:1px;height:40px;">${(p.dna?.hour_distribution||[]).map((v,i)=>`<div title="${i}:00 — ${v} events" style="flex:1;background:${v>0?'#3498db':'var(--border)'};height:${v?Math.max(4,v/Math.max(...(p.dna?.hour_distribution||[1]))*40):2}px;border-radius:1px;"></div>`).join('')}</div>
          <div style="display:flex;justify-content:space-between;font-size:0.6rem;color:var(--dim);"><span>0h</span><span>12h</span><span>23h</span></div>
        </div>
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Target Users</h4>
          ${(p.dna?.target_users||[]).map(u=>`<div style="font-family:monospace;font-size:0.75rem;">${esc(u)}</div>`).join('')||'<span style="color:var(--dim);font-size:0.75rem;">none</span>'}
        </div>
        <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Tool Signatures</h4>
          ${(p.dna?.tool_signatures||[]).map(t=>`<span style="padding:2px 6px;border-radius:4px;background:#1a2634;color:#3498db;font-size:0.7rem;margin:2px;">${esc(t)}</span>`).join('')||'<span style="color:var(--dim);font-size:0.75rem;">none</span>'}
        </div>
      </div>
    </div>`;

    // Honeypot Intel
    if (p.honeypot_sessions > 0) {
      html += `<div class="kpi-card" style="padding:16px;margin-top:16px;">
        <h3 style="margin:0 0 12px;display:flex;align-items:center;gap:8px">${lucideIcon('bug',{size:16})} Honeypot Intel</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
          <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Credentials Attempted</h4>
            <table style="font-size:0.75rem;"><tbody>
              ${(p.credentials_attempted||[]).slice(0,10).map(([u,pw])=>`<tr><td style="padding:1px 6px;font-family:monospace;">${esc(u)}</td><td style="padding:1px 6px;font-family:monospace;color:var(--dim);">${esc(pw)}</td></tr>`).join('')}
            </tbody></table>
          </div>
          <div><h4 style="font-size:0.8rem;color:var(--dim);margin:0 0 4px;">Commands Executed</h4>
            ${(p.commands_executed||[]).slice(0,10).map(c=>`<div style="font-family:monospace;font-size:0.7rem;padding:2px 0;border-bottom:1px solid var(--border);">${esc(c)}</div>`).join('')}
          </div>
        </div>
        ${(p.iocs?.urls||[]).length > 0 ? `<h4 style="font-size:0.8rem;color:var(--dim);margin:12px 0 4px;">IOCs</h4>
          ${(p.iocs.urls||[]).map(u=>`<div style="font-family:monospace;font-size:0.7rem;display:flex;align-items:center;gap:6px">${lucideIcon('link',{size:12})} ${esc(u)}</div>`).join('')}
          ${(p.iocs.ips||[]).map(i=>`<div style="font-family:monospace;font-size:0.7rem;display:flex;align-items:center;gap:6px">${lucideIcon('globe',{size:12})} ${esc(i)}</div>`).join('')}` : ''}
      </div>`;
    }

  return html;
}

// 2026-05-15 PR-A: shared dossier modal. The drill-down for an
// attacker IP is one DOM surface, opened from both Cases journey
// ("View full profile") and Intel profile-row clicks. Previously
// `openIntelProfile` did `showView('intel') → setTimeout(120ms) →
// switchIntelTab('profiles') → showProfileDetail` — that 120ms
// race lost when the Intel tab fetch out-ran the timer, leaving the
// operator on the generic profile list instead of the requested IP.
// The modal sidesteps that entirely: no tab switch, no race window.
async function openProfileModal(ip) {
  if (!ip) return;
  const modal = document.getElementById('profileModal');
  const title = document.getElementById('profileModalTitle');
  const body = document.getElementById('profileModalBody');
  if (!modal || !body) return;
  // Show the modal immediately with a loading state — operator gets
  // visual feedback the click registered even if the API is slow.
  if (title) title.textContent = 'Attacker dossier · ' + ip;
  body.innerHTML = '<div style="color:var(--muted);padding:24px;text-align:center">Loading…</div>';
  modal.style.display = 'flex';
  // Focus the close button for keyboard users; Escape closes (wired
  // by the document-level keydown handler below).
  const closeBtn = modal.querySelector('.enf-modal-close');
  if (closeBtn) closeBtn.focus();
  try {
    const p = await loadJson(`/api/attacker-profiles/${encodeURIComponent(ip)}`);
    // Re-check the modal is still open + still targeting THIS IP
    // (rapid-click protection — a second openProfileModal call would
    // have already overwritten the title with the new IP).
    if (modal.style.display === 'none') return;
    if (title && title.textContent !== 'Attacker dossier · ' + ip) return;
    body.innerHTML = renderProfileDossierHtml(p);
  } catch (e) {
    body.innerHTML = `<p style="color:#e74c3c;padding:16px">Failed to load: ${esc(e.message)}</p>`;
  }
}

function closeProfileModal() {
  const modal = document.getElementById('profileModal');
  if (!modal) return;
  modal.style.display = 'none';
  // Clear body so a follow-up open call starts from the loading
  // skeleton, not stale content from the previous IP.
  const body = document.getElementById('profileModalBody');
  if (body) body.innerHTML = '<div style="color:var(--muted);padding:24px;text-align:center">Loading…</div>';
}

// Escape-to-close. Single document-level listener so we never leak
// multiple handlers across re-opens.
if (typeof window !== 'undefined' && !window._profileModalEscBound) {
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      const modal = document.getElementById('profileModal');
      if (modal && modal.style.display !== 'none') closeProfileModal();
    }
  });
  window._profileModalEscBound = true;
}

// 2026-05-15 PR-A: `openIntelProfile` kept as a thin alias for
// backward compatibility with any cached call sites. New code MUST
// call `openProfileModal(ip)` directly.
function openIntelProfile(ip) {
  openProfileModal(ip);
}

// 2026-05-15 PR-C: Intel collapsed to a single surface — the Profiles
// list. PR-B removed Campaigns / Chains / MITRE sub-tabs; PR-C moves
// Baseline to the Health tab. With only one rendering left,
// `switchIntelTab` and `currentIntelTab` are gone — `loadIntel()` is
// the sole entry point and the sub-tab toolbar buttons are deleted
// from index.html. The pre-PR8 abort-controller (`_activeFetch_intel`)
// stays parked on `window` because `fetchAndRenderIntel` still attaches
// its signal there; without sub-tab cycling there's nothing to abort.
