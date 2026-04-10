// ── Responses tab ────────────────────────────────────────────────
async function loadResponses() {
  const status = document.getElementById('responsesViewStatus');
  const content = document.getElementById('responsesContent');
  if (status) status.textContent = 'Loading…';
  try {
    const r = await loadJson('/api/responses');
    let html = '';

    // KPI cards
    html += `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:16px;">
      <div class="kpi-card"><div class="kpi-value">${r.active_count||0}</div><div class="kpi-label">Active</div></div>
      <div class="kpi-card"><div class="kpi-value">${r.totals?.registered||0}</div><div class="kpi-label">Total</div></div>
      <div class="kpi-card"><div class="kpi-value">${r.totals?.expired||0}</div><div class="kpi-label">Expired</div></div>
      <div class="kpi-card"><div class="kpi-value">${r.totals?.reverted||0}</div><div class="kpi-label">Reverted</div></div>
    </div>`;

    // Active responses table
    if (r.active?.length > 0) {
      html += `<h3 style="margin:12px 0 8px;">Active Responses</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.8rem;">
        <thead><tr style="border-bottom:2px solid var(--border);text-align:left;">
          <th style="padding:6px;">Target</th><th style="padding:6px;">Backend</th>
          <th style="padding:6px;">Type</th><th style="padding:6px;">TTL</th>
          <th style="padding:6px;">Remaining</th><th style="padding:6px;">Incident</th>
        </tr></thead><tbody>`;
      r.active.forEach(a => {
        const mins = Math.floor((a.remaining_secs||0)/60);
        const hrs = Math.floor(mins/60);
        const remaining = hrs > 0 ? `${hrs}h ${mins%60}m` : `${mins}m`;
        const ttlH = Math.floor((a.ttl_secs||0)/3600);
        const backendColor = {xdp:'#e74c3c',iptables:'#f39c12',nftables:'#f39c12',ufw:'#3498db',cloudflare:'#f39c12',container:'#9b59b6',nginx:'#27ae60',sudo:'#e67e22'}[a.backend]||'var(--dim)';
        const backendTip = {xdp:'Kernel-level firewall (fastest)',iptables:'Linux packet filter',nftables:'Modern Linux firewall',ufw:'Ubuntu firewall',cloudflare:'Cloudflare edge rules',container:'Container runtime isolation',nginx:'Web server access control',sudo:'Privilege management'}[a.backend]||'';
        html += `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:6px;font-family:monospace;font-weight:600;">${a.target}</td>
          <td style="padding:6px;"><span title="${backendTip}" style="padding:2px 6px;border-radius:3px;background:${backendColor}20;color:${backendColor};font-size:0.7rem;cursor:help">${a.backend}</span></td>
          <td style="padding:6px;">${a.type}</td>
          <td style="padding:6px;">${ttlH}h</td>
          <td style="padding:6px;font-weight:600;color:${mins < 10 ? '#e74c3c' : 'var(--text)'};">${remaining}</td>
          <td style="padding:6px;font-size:0.7rem;color:var(--dim);">${(a.incident_id||'').substring(0,40)}</td>
        </tr>`;
      });
      html += '</tbody></table>';
    } else {
      html += '<p style="color:var(--dim);margin:20px 0;">No active responses. All blocks have expired or been reverted.</p>';
    }

    // History
    if (r.history?.length > 0) {
      html += `<h3 style="margin:20px 0 8px;">Recent History (${r.history.length})</h3>
        <table style="width:100%;border-collapse:collapse;font-size:0.75rem;">
        <thead><tr style="border-bottom:2px solid var(--border);text-align:left;">
          <th style="padding:4px 6px;">Target</th><th style="padding:4px 6px;">Backend</th>
          <th style="padding:4px 6px;">Reason</th><th style="padding:4px 6px;">Reverted At</th>
        </tr></thead><tbody>`;
      r.history.forEach(h => {
        const reasonColor = h.reason === 'expired' ? '#27ae60' : '#3498db';
        html += `<tr style="border-bottom:1px solid var(--border);">
          <td style="padding:4px 6px;font-family:monospace;">${h.target}</td>
          <td style="padding:4px 6px;">${h.backend}</td>
          <td style="padding:4px 6px;"><span style="color:${reasonColor}">${h.reason}</span></td>
          <td style="padding:4px 6px;color:var(--dim);">${new Date(h.reverted_at).toLocaleString()}</td>
        </tr>`;
      });
      html += '</tbody></table>';
    }

    content.innerHTML = html;
    if (status) status.textContent = `${r.active_count||0} active`;
  } catch(e) {
    content.innerHTML = `<p style="color:#e74c3c">Failed to load responses: ${e.message}</p>`;
    if (status) status.textContent = 'Error';
  }
}

