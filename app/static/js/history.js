/**
 * QShield Scan History Controller
 * Handles paginated fetching, filtering, safe detail viewing,
 * confirmation-guarded record deletion, and PDF report downloads.
 */

let currentPage = 1;
const pageLimit = 15;
let currentTotal = 0;
let pendingDeleteId = null;

document.addEventListener('DOMContentLoaded', () => {
  loadHistory(1);
});

async function loadHistory(page = 1) {
  currentPage = page;
  const tbody = document.getElementById('historyTbody');
  const emptyState = document.getElementById('emptyState');
  const tableContainer = document.getElementById('tableContainer');
  const paginationBar = document.getElementById('paginationBar');

  const category = document.getElementById('filterCategory').value;
  const risk = document.getElementById('filterRisk').value;
  const status = document.getElementById('filterStatus').value;
  const search = document.getElementById('searchInput').value.trim();

  const params = new URLSearchParams({
    page: page,
    limit: pageLimit
  });

  if (category) params.append('payload_type', category);
  if (risk) params.append('risk_level', risk);
  if (status) params.append('status', status);
  if (search) params.append('search', search);

  try {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding: 2rem; color: var(--color-text-secondary);">Loading scan records...</td></tr>';

    const res = await fetch(`/api/scan-history?${params.toString()}`);
    const data = await res.json();

    if (data.success && data.history && data.history.length > 0) {
      currentTotal = data.total || data.history.length;
      renderTable(data.history);
      updatePagination(data.page, data.total, data.limit);
      tableContainer.style.display = 'block';
      paginationBar.style.display = 'flex';
      emptyState.style.display = 'none';
    } else {
      tbody.innerHTML = '';
      tableContainer.style.display = 'none';
      paginationBar.style.display = 'none';
      emptyState.style.display = 'block';
    }
  } catch (err) {
    console.error('Failed to load scan history:', err);
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; padding: 2rem; color: #ef4444;">Failed to load records. Please refresh the page.</td></tr>`;
  }
}

function renderTable(records) {
  const tbody = document.getElementById('historyTbody');
  tbody.innerHTML = '';

  records.forEach(r => {
    const tr = document.createElement('tr');

    const riskLevel = (r.risk_level || 'inconclusive').toLowerCase();
    const badgeClass = getRiskBadgeClass(riskLevel);
    const scoreText = (r.risk_score !== null && r.risk_score !== undefined) ? `${r.risk_score}/100` : '—';
    const domainText = r.target_domain ? escapeHtml(r.target_domain) : '<span style="color:var(--color-text-muted);">None / Masked</span>';
    const statusText = escapeHtml(r.status || 'completed');

    tr.innerHTML = `
      <td><strong>#${r.id}</strong></td>
      <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--color-text-secondary);">${escapeHtml(r.created_at)}</td>
      <td><span class="hero-badge" style="font-size: 0.7rem;">${escapeHtml(r.scan_type || 'unknown')}</span></td>
      <td>${escapeHtml(r.payload_type || 'Unknown')}</td>
      <td>${domainText}</td>
      <td><span class="card-badge ${badgeClass}" style="font-size: 0.75rem; text-transform: capitalize;">${escapeHtml(riskLevel)}</span></td>
      <td><strong>${scoreText}</strong></td>
      <td><span style="font-size: 0.8rem; color: ${statusText === 'completed' ? 'var(--color-teal)' : 'var(--color-text-muted)'}; font-weight:600;">${statusText}</span></td>
      <td>
        <div class="table-actions">
          <button type="button" class="btn-icon" title="View Record Details" onclick="openDetailModal(${r.id})">
            ℹ️ Details
          </button>
          <a href="/api/scan-history/${r.id}/report" class="btn-icon" title="Download PDF Summary Report" target="_blank">
            📥 PDF
          </a>
          <button type="button" class="btn-icon btn-icon-danger" title="Delete Record" onclick="confirmDelete(${r.id})">
            🗑
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function getRiskBadgeClass(level) {
  switch (level) {
    case 'low': return 'badge-implemented';
    case 'medium': return 'badge-planned';
    case 'high':
    case 'critical': return 'badge-planned';
    default: return 'badge-planned';
  }
}

function updatePagination(page, total, limit) {
  const info = document.getElementById('paginationInfo');
  const pageDisplay = document.getElementById('pageNumberDisplay');
  const btnPrev = document.getElementById('btnPrevPage');
  const btnNext = document.getElementById('btnNextPage');

  const totalPages = Math.ceil(total / limit) || 1;
  const start = Math.min((page - 1) * limit + 1, total);
  const end = Math.min(page * limit, total);

  info.textContent = `Showing ${start}-${end} of ${total} records`;
  pageDisplay.textContent = `Page ${page} of ${totalPages}`;

  btnPrev.disabled = (page <= 1);
  btnNext.disabled = (page >= totalPages);
}

function changePage(delta) {
  const newPage = currentPage + delta;
  if (newPage >= 1) {
    loadHistory(newPage);
  }
}

function applyFilters() {
  loadHistory(1);
}

function resetFilters() {
  document.getElementById('filterCategory').value = '';
  document.getElementById('filterRisk').value = '';
  document.getElementById('filterStatus').value = '';
  document.getElementById('searchInput').value = '';
  loadHistory(1);
}

/* ── Details Modal ── */
async function openDetailModal(scanId) {
  const modal = document.getElementById('detailModal');
  const body = document.getElementById('modalBody');
  const title = document.getElementById('modalTitle');
  const pdfBtn = document.getElementById('modalDownloadPdfBtn');

  title.textContent = `Scan Record #${scanId}`;
  pdfBtn.href = `/api/scan-history/${scanId}/report`;
  body.innerHTML = '<p style="color:var(--color-text-secondary);">Loading details...</p>';
  modal.style.display = 'flex';

  try {
    const res = await fetch(`/api/scan-history/${scanId}`);
    const data = await res.json();
    if (data.success && data.scan) {
      const s = data.scan;
      const scoreStr = (s.risk_score !== null && s.risk_score !== undefined) ? `${s.risk_score}/100` : 'Not Scored';

      body.innerHTML = `
        <div style="background:var(--color-bg-surface); padding:var(--space-md); border-radius:var(--radius-md); border:1px solid var(--color-border);">
          <div style="margin-bottom:0.4rem;"><strong>Record ID:</strong> #${s.id}</div>
          <div style="margin-bottom:0.4rem;"><strong>Timestamp (UTC):</strong> ${escapeHtml(s.created_at)}</div>
          <div style="margin-bottom:0.4rem;"><strong>Submission Type:</strong> ${escapeHtml(s.scan_type)}</div>
          <div style="margin-bottom:0.4rem;"><strong>Payload Category:</strong> ${escapeHtml(s.payload_type)}</div>
          <div style="margin-bottom:0.4rem;"><strong>Sanitized Target:</strong> ${s.target_domain ? escapeHtml(s.target_domain) : 'None / Not applicable'}</div>
          <div style="margin-bottom:0.4rem;"><strong>Heuristic Score:</strong> ${scoreStr} (${escapeHtml(s.risk_level || 'inconclusive')})</div>
          <div style="margin-bottom:0.4rem;"><strong>Indicators Count:</strong> ${s.indicator_count}</div>
          <div><strong>Status:</strong> ${escapeHtml(s.status)}</div>
        </div>
        <p style="font-size:0.775rem; color:var(--color-text-muted); margin:0.5rem 0 0;">
          <strong>Privacy Retention Note:</strong> In strict compliance with QShield’s privacy architecture, full decoded payloads and URLs are discarded immediately upon scanning. Only non-sensitive metadata is retained.
        </p>
      `;
    } else {
      body.innerHTML = '<p style="color:#ef4444;">Record not found.</p>';
    }
  } catch (err) {
    body.innerHTML = '<p style="color:#ef4444;">Error fetching record details.</p>';
  }
}

function closeDetailModal() {
  document.getElementById('detailModal').style.display = 'none';
}

/* ── Deletion Modal ── */
function confirmDelete(scanId) {
  pendingDeleteId = scanId;
  const modal = document.getElementById('deleteModal');
  const text = document.getElementById('deleteModalText');
  text.textContent = `Are you sure you want to permanently delete scan record #${scanId}? This action cannot be undone.`;
  modal.style.display = 'flex';
}

function closeDeleteModal() {
  pendingDeleteId = null;
  document.getElementById('deleteModal').style.display = 'none';
}

async function executeDelete() {
  if (!pendingDeleteId) return;

  const btn = document.getElementById('confirmDeleteBtn');
  btn.disabled = true;
  btn.textContent = 'Deleting...';

  try {
    const res = await fetch(`/api/scan-history/${pendingDeleteId}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (data.success) {
      closeDeleteModal();
      loadHistory(currentPage);
    } else {
      alert(data.message || 'Failed to delete record.');
    }
  } catch (err) {
    console.error('Delete error:', err);
    alert('An error occurred while deleting the record.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Yes, Delete Record';
    pendingDeleteId = null;
  }
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
