/**
 * QShield Threat Intelligence Dashboard & QR Risk Analytics Controller
 * Provides reactive filtering, SVG timeline visualization, risk distributions,
 * observed indicators aggregation, and PDF report export.
 * Operates strictly on sanitized database metadata without displaying sensitive payloads.
 */

let currentTimeRange = '7d';
let currentRiskLevel = 'all';
let currentPayloadType = 'all';

document.addEventListener('DOMContentLoaded', () => {
  const savedKey = sessionStorage.getItem('qshield_admin_key');
  if (savedKey) {
    const input = document.getElementById('adminKeyInput');
    if (input) input.value = savedKey;
  }
  loadAllAnalytics();
});

function getAdminHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  const key = sessionStorage.getItem('qshield_admin_key');
  if (key) {
    headers['X-Admin-Key'] = key;
  }
  return headers;
}

window.saveAdminKey = function() {
  const input = document.getElementById('adminKeyInput');
  const key = input ? input.value.trim() : '';
  if (key) {
    sessionStorage.setItem('qshield_admin_key', key);
  } else {
    sessionStorage.removeItem('qshield_admin_key');
  }
  loadAllAnalytics();
};

window.setTimeRange = function(range) {
  currentTimeRange = range;
  document.querySelectorAll('.filter-time-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-range') === range);
  });
  updateActiveFilterLabel();
  loadAllAnalytics();
};

window.applyFilters = function() {
  const rEl = document.getElementById('filterRiskLevel');
  const pEl = document.getElementById('filterPayloadType');
  if (rEl) currentRiskLevel = rEl.value;
  if (pEl) currentPayloadType = pEl.value;
  updateActiveFilterLabel();
  loadAllAnalytics();
};

window.resetFilters = function() {
  currentTimeRange = '7d';
  currentRiskLevel = 'all';
  currentPayloadType = 'all';

  document.querySelectorAll('.filter-time-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-range') === '7d');
  });
  const rEl = document.getElementById('filterRiskLevel');
  const pEl = document.getElementById('filterPayloadType');
  if (rEl) rEl.value = 'all';
  if (pEl) pEl.value = 'all';

  updateActiveFilterLabel();
  loadAllAnalytics();
};

function updateActiveFilterLabel() {
  const labelEl = document.getElementById('activeFilterLabel');
  if (!labelEl) return;

  const rangeLabels = {
    '24h': 'Last 24 Hours',
    '7d': 'Last 7 Days',
    '30d': 'Last 30 Days',
    'all': 'All Time Records'
  };
  const rText = currentRiskLevel === 'all' ? 'All Risk Levels' : `${capitalize(currentRiskLevel)} Risk`;
  const pText = currentPayloadType === 'all' ? 'All Categories' : currentPayloadType;

  labelEl.textContent = `Active View: ${rangeLabels[currentTimeRange] || 'Selected Range'} • ${rText} • ${pText}`;
}

function buildQueryString() {
  const params = new URLSearchParams();
  params.append('time_range', currentTimeRange);
  if (currentRiskLevel !== 'all') params.append('risk_level', currentRiskLevel);
  if (currentPayloadType !== 'all') params.append('payload_type', currentPayloadType);
  return params.toString();
}

window.exportAnalyticsPdf = function() {
  const qs = buildQueryString();
  const url = `/api/analytics/export-pdf?${qs}`;
  const key = sessionStorage.getItem('qshield_admin_key');
  if (key) {
    // If admin key set, fetch as blob to pass header
    fetch(url, { headers: getAdminHeaders() })
      .then(res => {
        if (!res.ok) throw new Error('PDF export failed');
        return res.blob();
      })
      .then(blob => {
        const dlUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = dlUrl;
        a.download = `qshield-threat-analytics-${currentTimeRange}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(dlUrl);
      })
      .catch(err => {
        alert('Failed to download PDF report: ' + err.message);
      });
  } else {
    // Standard direct browser trigger
    window.location.href = url;
  }
};

async function loadAllAnalytics() {
  const updatedEl = document.getElementById('lastUpdatedLabel');
  if (updatedEl) updatedEl.textContent = 'Updating...';

  await Promise.all([
    fetchSummary(),
    fetchTrends(),
    fetchTimeline(),
    fetchRiskDistribution(),
    fetchPayloadCategories(),
    fetchDetectionMethods(),
    fetchIndicators(),
    fetchHealth(),
    fetchRecentActivity()
  ]);

  if (updatedEl) {
    const now = new Date();
    updatedEl.textContent = `Updated: ${now.toLocaleTimeString()}`;
  }
}

async function fetchSummary() {
  try {
    const qs = buildQueryString();
    const res = await fetch(`/api/analytics/summary?${qs}`, { headers: getAdminHeaders() });
    const data = await res.json();

    if (res.status === 401 || res.status === 403) {
      handleAuthError(data.message);
      return;
    }

    if (data.success && data.summary) {
      const s = data.summary;
      const totalEl = document.getElementById('metricTotalScans') || document.getElementById('kpiTotalScans');
      if (totalEl) totalEl.textContent = s.total_scans;
      const totalSub = document.getElementById('kpiTotalScansSub');
      if (totalSub) totalSub.textContent = `In ${s.time_range.replace(/_/g, ' ')}`;

      const highCritEl = document.getElementById('kpiHighCritScans');
      if (highCritEl) highCritEl.textContent = s.high_or_critical_scans;
      const pctHigh = s.total_scans > 0 ? Math.round((s.high_or_critical_scans / s.total_scans) * 100) : 0;
      const highSub = document.getElementById('kpiHighCritSub');
      if (highSub) highSub.textContent = `${pctHigh}% of scans in period (${s.high_risk_scans} High, ${s.critical_risk_scans} Crit)`;

      const inconcEl = document.getElementById('kpiInconclusiveScans');
      if (inconcEl) inconcEl.textContent = s.inconclusive_scans;
      const threatEl = document.getElementById('kpiThreatDetections');
      if (threatEl) threatEl.textContent = s.external_threat_detections;
      
      const threatSub = document.getElementById('kpiThreatDetectionsSub');
      if (threatSub) {
        if (s.external_threat_provider_configured) {
          threatSub.textContent = `Provider active (${s.external_threat_detections} matches)`;
        } else {
          threatSub.textContent = 'External provider not configured';
        }
      }

      const avgEl = document.getElementById('metricAvgScore') || document.getElementById('kpiAvgScore');
      if (avgEl) avgEl.textContent = s.avg_risk_score !== null ? `${s.avg_risk_score}/100` : '—';
      const scoredCountEl = document.getElementById('kpiScoredCount');
      if (scoredCountEl) scoredCountEl.textContent = `Across ${s.scored_scans} scored URL payloads`;
    }
  } catch (err) {
    console.error('Failed to load analytics summary:', err);
  }
}

async function fetchTrends() {
  try {
    const res = await fetch(`/api/analytics/trends?time_range=${currentTimeRange}`, { headers: getAdminHeaders() });
    const data = await res.json();

    if (data.success && data.trends) {
      const t = data.trends;
      const bannerTitle = document.getElementById('trendBannerTitle');
      const bannerDesc = document.getElementById('trendBannerDesc');
      const chipsWrap = document.getElementById('trendChipsWrap');

      bannerTitle.textContent = `${t.period_label} — Shift Analysis`;
      bannerDesc.textContent = t.summary_message + ' ' + t.disclaimer;

      chipsWrap.innerHTML = '';

      if (!t.has_sufficient_data) {
        chipsWrap.innerHTML = `
          <span class="trend-chip trend-neutral">
            <span>●</span> Not enough data to identify a trend (&lt;5 records)
          </span>
        `;
        return;
      }

      const m = t.metrics || {};
      
      // Total scans chip
      chipsWrap.appendChild(createTrendChip('Scans', m.total_scans, 'total'));
      // High/Critical Threats chip
      chipsWrap.appendChild(createTrendChip('Threats', m.high_or_critical_scans, 'threats'));
      // Avg Score chip
      if (m.avg_risk_score) {
        chipsWrap.appendChild(createTrendChip('Avg Risk', m.avg_risk_score, 'score'));
      }
    }
  } catch (err) {
    console.error('Failed to load trends:', err);
  }
}

function createTrendChip(label, deltaObj, type) {
  const chip = document.createElement('span');
  if (!deltaObj) {
    chip.className = 'trend-chip trend-neutral';
    chip.textContent = `${label}: —`;
    return chip;
  }

  const change = deltaObj.absolute_change || 0;
  const pct = deltaObj.percentage_change;
  const sign = change > 0 ? '+' : '';

  let className = 'trend-neutral';
  let arrow = '●';

  if (change > 0) {
    arrow = '▲';
    className = (type === 'threats' || type === 'score') ? 'trend-up' : 'trend-down';
  } else if (change < 0) {
    arrow = '▼';
    className = (type === 'threats' || type === 'score') ? 'trend-down' : 'trend-up';
  }

  chip.className = `trend-chip ${className}`;
  const pctText = pct !== null && pct !== undefined ? ` (${sign}${pct}%)` : ' (new activity)';
  chip.innerHTML = `<span>${arrow}</span> <strong>${label}:</strong> ${sign}${change}${pctText}`;
  return chip;
}

async function fetchTimeline() {
  try {
    const qs = buildQueryString();
    const res = await fetch(`/api/analytics/activity?${qs}`, { headers: getAdminHeaders() });
    const data = await res.json();

    const container = document.getElementById('timelineChartContainer');
    if (!container) return;

    if (data.success && data.activity) {
      renderSvgTimeline(data.activity, container);
    }
  } catch (err) {
    console.error('Failed to load timeline:', err);
  }
}

function renderSvgTimeline(activity, container) {
  container.innerHTML = '';
  const timeline = activity.timeline || [];

  if (timeline.length === 0 || activity.is_empty) {
    container.innerHTML = `
      <div style="text-align: center; padding: 2.5rem 1rem; color: var(--color-text-muted); font-size: 0.85rem;">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom:0.5rem; opacity:0.5;">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
        <div>No scan records observed in the selected time range.</div>
      </div>
    `;
    return;
  }

  // Dimensions
  const height = 180;
  const margin = { top: 20, right: 20, bottom: 35, left: 35 };
  const minWidth = Math.max(timeline.length * 32, 450);
  const width = minWidth;

  const maxVal = Math.max(...timeline.map(d => d.total), 5);
  const chartH = height - margin.top - margin.bottom;
  const chartW = width - margin.left - margin.right;
  const slotW = chartW / timeline.length;
  const barW = Math.max(slotW * 0.55, 6);

  let svgHtml = `<svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="overflow: visible; font-family: var(--font-sans);" role="img" aria-label="Scan Activity Timeline Chart">`;

  // Grid lines
  for (let step = 0; step <= 4; step++) {
    const val = Math.round((maxVal / 4) * step);
    const y = margin.top + chartH - (val / maxVal) * chartH;
    svgHtml += `
      <line x1="${margin.left}" y1="${y}" x2="${width - margin.right}" y2="${y}" stroke="var(--color-border)" stroke-dasharray="2,2" stroke-width="0.8" />
      <text x="${margin.left - 6}" y="${y + 3}" fill="var(--color-text-muted)" font-size="9" text-anchor="end">${val}</text>
    `;
  }

  // Bars and points
  timeline.forEach((d, idx) => {
    const cx = margin.left + (idx + 0.5) * slotW;
    const totalH = (d.total / maxVal) * chartH;
    const threatH = (d.high_or_critical / maxVal) * chartH;
    const yTotal = margin.top + chartH - totalH;
    const yThreat = margin.top + chartH - threatH;

    // Total bar (Teal)
    svgHtml += `
      <rect x="${cx - barW / 2}" y="${yTotal}" width="${barW}" height="${totalH}" fill="var(--color-teal)" rx="2" opacity="0.85">
        <title>${escapeHtml(d.bucket)}: ${d.total} total scan(s)</title>
      </rect>
    `;

    // Elevated threat bar (Red overlay)
    if (d.high_or_critical > 0) {
      svgHtml += `
        <rect x="${cx - barW / 2}" y="${yThreat}" width="${barW}" height="${threatH}" fill="#ef4444" rx="2" opacity="0.95">
          <title>${escapeHtml(d.bucket)}: ${d.high_or_critical} high/critical threat(s)</title>
        </rect>
      `;
    }

    // X-axis label (show subset to avoid clutter)
    const showLabel = timeline.length <= 14 || idx % Math.ceil(timeline.length / 10) === 0 || idx === timeline.length - 1;
    if (showLabel) {
      svgHtml += `
        <text x="${cx}" y="${height - 12}" fill="var(--color-text-secondary)" font-size="9" text-anchor="middle">
          ${escapeHtml(d.label)}
        </text>
      `;
    }
  });

  // Base axis line
  svgHtml += `
    <line x1="${margin.left}" y1="${margin.top + chartH}" x2="${width - margin.right}" y2="${margin.top + chartH}" stroke="var(--color-border)" stroke-width="1.2" />
  `;

  svgHtml += `</svg>`;
  container.innerHTML = svgHtml;
}

async function fetchRiskDistribution() {
  try {
    const qs = buildQueryString();
    const res = await fetch(`/api/analytics/risk-distribution?${qs}`, { headers: getAdminHeaders() });
    const data = await res.json();

    const segBar = document.getElementById('riskSegmentedBar');
    const container = document.getElementById('riskDistContainer');
    if (!container || !segBar) return;

    if (data.success && data.risk_distribution) {
      const rd = data.risk_distribution;
      const list = rd.distribution || [];

      segBar.innerHTML = '';
      container.innerHTML = '';

      if (rd.is_empty) {
        segBar.innerHTML = '<div class="segmented-slice" style="width:100%; background:var(--color-border);"></div>';
        container.innerHTML = '<div style="color:var(--color-text-muted); font-size:0.85rem; padding:1.5rem 0;">No risk evaluations recorded in this period.</div>';
        return;
      }

      list.forEach(item => {
        // Segment slice
        if (item.percentage > 0) {
          const slice = document.createElement('div');
          slice.className = 'segmented-slice';
          slice.style.width = `${item.percentage}%`;
          slice.style.backgroundColor = item.color;
          slice.title = `${item.name}: ${item.count} (${item.percentage}%)`;
          segBar.appendChild(slice);
        }

        // Row details
        const row = document.createElement('div');
        row.className = 'dist-row';
        row.innerHTML = `
          <div class="dist-row-header">
            <div>
              <span style="font-weight: 600; color: ${item.color};">● ${escapeHtml(item.name)}</span>
              <span style="font-size: 0.725rem; color: var(--color-text-muted); margin-left: 0.35rem;">(${escapeHtml(item.score_range)})</span>
            </div>
            <span style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 600;">
              ${item.count} (${item.percentage}%)
            </span>
          </div>
          <div class="dist-bar-wrap">
            <div class="dist-bar-fill" style="width: ${item.percentage}%; background: ${item.color};"></div>
          </div>
          <div style="font-size: 0.725rem; color: var(--color-text-secondary); margin-top: 1px;">
            ${escapeHtml(item.description)}
          </div>
        `;
        container.appendChild(row);
      });
    }
  } catch (err) {
    console.error('Failed to load risk distribution:', err);
  }
}

async function fetchPayloadCategories() {
  try {
    const qs = buildQueryString();
    const res = await fetch(`/api/analytics/payload-categories?${qs}`, { headers: getAdminHeaders() });
    const data = await res.json();

    const container = document.getElementById('payloadDistContainer');
    if (!container) return;

    if (data.success && data.payload_categories) {
      const pc = data.payload_categories;
      const list = pc.categories || [];
      container.innerHTML = '';

      if (pc.is_empty || list.length === 0) {
        container.innerHTML = '<div style="color:var(--color-text-muted); font-size:0.85rem; padding:1.5rem 0;">No payloads recorded in this period.</div>';
        return;
      }

      list.forEach(cat => {
        const row = document.createElement('div');
        row.className = 'dist-row';
        row.innerHTML = `
          <div class="dist-row-header">
            <span style="font-weight: 500;">${escapeHtml(cat.category)}</span>
            <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--color-text-secondary);">
              ${cat.count} (${cat.percentage}%)
            </span>
          </div>
          <div class="dist-bar-wrap">
            <div class="dist-bar-fill" style="width: ${cat.percentage}%; background: var(--color-teal);"></div>
          </div>
        `;
        container.appendChild(row);
      });
    }
  } catch (err) {
    console.error('Failed to load payload categories:', err);
  }
}

async function fetchDetectionMethods() {
  try {
    const qs = buildQueryString();
    const res = await fetch(`/api/analytics/detection-methods?${qs}`, { headers: getAdminHeaders() });
    const data = await res.json();

    const container = document.getElementById('detectionMethodsContainer');
    if (!container) return;

    if (data.success && data.detection_methods) {
      const dm = data.detection_methods;
      const methods = dm.methods || [];
      container.innerHTML = '';

      methods.forEach(m => {
        const card = document.createElement('div');
        card.style.background = 'var(--color-bg-surface)';
        card.style.padding = 'var(--space-md)';
        card.style.borderRadius = 'var(--radius-md)';
        card.style.border = '1px solid var(--color-border)';

        card.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-size:0.75rem; text-transform:uppercase; font-weight:700; color:var(--color-text-muted);">${escapeHtml(m.id)}</span>
            <span style="font-family:var(--font-mono); font-size:0.8rem; font-weight:700; color:var(--color-teal);">${m.count} scans (${m.percentage}%)</span>
          </div>
          <div style="font-weight:700; font-size:0.95rem; margin:0.3rem 0 0.2rem;">${escapeHtml(m.name)}</div>
          <div style="font-size:0.75rem; color:var(--color-text-secondary); line-height:1.4;">${escapeHtml(m.description)}</div>
        `;
        container.appendChild(card);
      });

      // External reputation card
      const rep = dm.external_reputation_checks || {};
      const repCard = document.createElement('div');
      repCard.style.background = 'var(--color-bg-surface)';
      repCard.style.padding = 'var(--space-md)';
      repCard.style.borderRadius = 'var(--radius-md)';
      repCard.style.border = '1px solid var(--color-border)';
      repCard.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span style="font-size:0.75rem; text-transform:uppercase; font-weight:700; color:var(--color-text-muted);">external_reputation</span>
          <span style="font-family:var(--font-mono); font-size:0.8rem; font-weight:700; color:#ef4444;">${rep.flagged_matches || 0} flagged</span>
        </div>
        <div style="font-weight:700; font-size:0.95rem; margin:0.3rem 0 0.2rem;">Threat Feed Checks</div>
        <div style="font-size:0.75rem; color:var(--color-text-secondary); line-height:1.4;">
          ${rep.total_performed || 0} checks performed with user consent (${rep.clean_or_neutral || 0} clean / neutral).
        </div>
      `;
      container.appendChild(repCard);
    }
  } catch (err) {
    console.error('Failed to load detection methods:', err);
  }
}

async function fetchIndicators() {
  try {
    const qs = buildQueryString();
    const res = await fetch(`/api/analytics/indicators?${qs}`, { headers: getAdminHeaders() });
    const data = await res.json();

    const tbody = document.getElementById('indicatorsTbody');
    if (!tbody) return;

    if (data.success && data.indicators) {
      const ind = data.indicators;
      const list = ind.indicators || [];
      tbody.innerHTML = '';

      if (ind.is_empty || list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:1.5rem; color:var(--color-text-muted);">No risk indicators recorded in this period.</td></tr>';
        return;
      }

      list.forEach(item => {
        const tr = document.createElement('tr');
        const sevClass = `severity-${(item.severity || 'medium').toLowerCase()}`;
        const catBadge = item.category === 'external_confirmed' ? 'Threat Feed' : 'Structural';
        const catColor = item.category === 'external_confirmed' ? '#ef4444' : 'var(--color-teal)';

        tr.innerHTML = `
          <td style="font-weight: 600;">${escapeHtml(item.name)}</td>
          <td><span style="font-size:0.75rem; font-weight:600; color:${catColor};">${catBadge}</span></td>
          <td><span class="severity-badge ${sevClass}">${escapeHtml(item.severity)}</span></td>
          <td style="font-family: var(--font-mono); font-weight: 600;">${item.count}</td>
          <td style="font-family: var(--font-mono); color: var(--color-text-secondary);">${item.percentage}%</td>
          <td style="font-size: 0.775rem; color: var(--color-text-secondary); max-width: 320px;">${escapeHtml(item.description)}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Failed to load indicators:', err);
  }
}

async function fetchHealth() {
  try {
    const res = await fetch('/api/admin/health', { headers: getAdminHeaders() });
    const data = await res.json();

    if (data.success && data.health) {
      const h = data.health;
      const dbEl = document.getElementById('healthDbStatus');
      const threatEl = document.getElementById('healthThreatStatus');
      const authTitle = document.getElementById('authStatusTitle');
      const authDesc = document.getElementById('authStatusDesc');

      if (dbEl) {
        dbEl.textContent = h.database_connected ? '● Connected (SQLite)' : '○ Database Disconnected';
        dbEl.style.color = h.database_connected ? '#22c55e' : '#ef4444';
      }

      if (threatEl) {
        if (h.threat_intelligence_configured) {
          threatEl.textContent = `● Configured (${h.threat_intel_provider})`;
          threatEl.style.color = '#22c55e';
        } else {
          threatEl.textContent = '○ Available On Demand (Not configured)';
          threatEl.style.color = '#f59e0b';
        }
      }

      if (h.admin_auth_mode === 'key_enforced') {
        if (authTitle) authTitle.textContent = 'Key Authorization Enforced:';
        if (authDesc) authDesc.textContent = 'Admin analytics APIs are protected with an active API key check.';
        const banner = document.getElementById('authNoticeBanner');
        if (banner) banner.style.borderLeftColor = 'var(--color-teal)';
      }
    }
  } catch (err) {
    console.error('Failed to load admin health:', err);
  }
}

async function fetchRecentActivity() {
  try {
    const res = await fetch('/api/admin/summary', { headers: getAdminHeaders() });
    const data = await res.json();

    const tbody = document.getElementById('recentActivityTbody');
    if (!tbody) return;

    if (data.success && data.metrics) {
      const records = data.metrics.recent_activity || [];
      tbody.innerHTML = '';

      if (records.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:1.5rem; color:var(--color-text-muted);">No recent activity recorded.</td></tr>';
        return;
      }

      records.forEach(r => {
        const tr = document.createElement('tr');
        const riskLevel = (r.risk_level || 'inconclusive').toLowerCase();
        const domain = r.target_domain ? escapeHtml(r.target_domain) : '<span style="color:var(--color-text-muted);">None</span>';
        const statusText = escapeHtml(r.status || 'completed');

        tr.innerHTML = `
          <td style="padding: 0.6rem 0.8rem;"><strong>#${r.id}</strong></td>
          <td style="padding: 0.6rem 0.8rem; font-family: var(--font-mono); font-size: 0.775rem; color: var(--color-text-secondary);">${escapeHtml(r.created_at)}</td>
          <td style="padding: 0.6rem 0.8rem;"><span class="hero-badge" style="font-size: 0.68rem;">${escapeHtml(r.scan_type || 'unknown')}</span></td>
          <td style="padding: 0.6rem 0.8rem;">${escapeHtml(r.payload_type || 'Unknown')}</td>
          <td style="padding: 0.6rem 0.8rem;">${domain}</td>
          <td style="padding: 0.6rem 0.8rem;"><span style="font-size:0.8rem; font-weight:600; text-transform:capitalize; color:${getRiskColor(riskLevel)};">${escapeHtml(riskLevel)}</span></td>
          <td style="padding: 0.6rem 0.8rem; font-size:0.8rem; font-weight:600; color:${statusText === 'completed' ? 'var(--color-teal)' : 'var(--color-text-muted)'};">${statusText}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Failed to load recent activity:', err);
  }
}

function handleAuthError(msg) {
  const authTitle = document.getElementById('authStatusTitle');
  const authDesc = document.getElementById('authStatusDesc');
  const banner = document.getElementById('authNoticeBanner');
  if (authTitle) authTitle.textContent = 'Access Restricted:';
  if (authDesc) authDesc.textContent = msg || 'Authorization key required to view admin analytics telemetry.';
  if (banner) banner.style.borderLeftColor = '#ef4444';
}

function getRiskColor(level) {
  switch ((level || '').toLowerCase()) {
    case 'low': return '#22c55e';
    case 'medium': return '#f59e0b';
    case 'high': return '#ef4444';
    case 'critical': return '#7f1d1d';
    default: return '#6b7280';
  }
}

function capitalize(s) {
  if (!s) return '';
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
