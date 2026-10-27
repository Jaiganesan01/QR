/**
 * QShield Awareness Centre Script
 * Handles bilingual (English & Tamil) toggle, client-side search,
 * interactive scenarios, and local storage-backed checklist.
 */

let currentLang = localStorage.getItem('qshield_awareness_lang') || 'en';
let localeData = {};
let guidesCache = [];
let scenariosCache = [];
let checklistCache = [];

document.addEventListener('DOMContentLoaded', async () => {
  await loadLanguage(currentLang);
  initSearch();
  initChecklistState();
});

async function loadLanguage(lang) {
  currentLang = lang;
  localStorage.setItem('qshield_awareness_lang', lang);

  // Update toggle buttons active state
  const btnEn = document.getElementById('btnLangEn');
  const btnTa = document.getElementById('btnLangTa');
  if (btnEn && btnTa) {
    if (lang === 'ta') {
      btnTa.classList.add('active');
      btnEn.classList.remove('active');
    } else {
      btnEn.classList.add('active');
      btnTa.classList.remove('active');
    }
  }

  try {
    const res = await fetch(`/api/locale/${lang}`);
    const json = await res.json();
    if (json.success && json.data) {
      localeData = json.data;
      applyTranslations();
      renderGuides();
      renderScenarios();
      renderChecklist();
      filterGuides(); // Re-apply search filter if any
    }
  } catch (err) {
    console.error('Failed to load locale:', err);
  }
}

window.switchLanguage = function(lang) {
  if (lang !== currentLang) {
    loadLanguage(lang);
  }
};

function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (localeData[key]) {
      el.textContent = localeData[key];
    }
  });

  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (localeData[key]) {
      el.setAttribute('placeholder', localeData[key]);
    }
  });
}

function renderGuides() {
  const container = document.getElementById('guidesGrid');
  if (!container || !localeData.guides) return;

  guidesCache = Object.values(localeData.guides);
  container.innerHTML = '';

  guidesCache.forEach(g => {
    const card = document.createElement('div');
    card.className = 'guide-card';
    card.id = g.id;
    card.setAttribute('data-guide-id', g.id);
    card.setAttribute('data-guide-title', g.title.toLowerCase());
    card.setAttribute('data-guide-desc', g.desc.toLowerCase());

    const pointsHtml = (g.points || []).map(p => `<li>${escapeHtml(p)}</li>`).join('');

    card.innerHTML = `
      <div>
        <div class="hero-badge" style="font-size: 0.75rem; margin-bottom: var(--space-xs);">${escapeHtml(g.badge)}</div>
        <h3 style="margin-bottom: var(--space-xs); font-size: 1.25rem;">${escapeHtml(g.title)}</h3>
        <p style="color: var(--color-text-secondary); font-size: var(--text-sm); line-height: 1.5; margin-bottom: var(--space-md);">${escapeHtml(g.desc)}</p>
      </div>
      <ul class="guide-points">
        ${pointsHtml}
      </ul>
    `;
    container.appendChild(card);
  });
}

function renderScenarios() {
  const container = document.getElementById('scenariosContainer');
  if (!container || !localeData.scenarios) return;

  scenariosCache = localeData.scenarios;
  container.innerHTML = '';

  scenariosCache.forEach((scen, sIndex) => {
    const card = document.createElement('div');
    card.className = 'scenario-card';
    card.id = scen.id;

    const optionsHtml = scen.options.map((opt, oIndex) => `
      <label class="option-label">
        <input type="radio" name="scen_${sIndex}" value="${oIndex}" onchange="checkScenario(${sIndex}, ${oIndex}, ${scen.correct_index})">
        <span style="font-size: var(--text-sm); color: var(--color-text-primary);">${escapeHtml(opt)}</span>
      </label>
    `).join('');

    card.innerHTML = `
      <div class="hero-badge" style="font-size: 0.75rem; margin-bottom: var(--space-xs);">${currentLang === 'ta' ? 'ஊடாடும் பயிற்சி' : 'Interactive Case'}</div>
      <h3 style="margin-bottom: var(--space-sm); font-size: 1.25rem;">${escapeHtml(scen.title)}</h3>
      <p style="color: var(--color-text-secondary); font-size: var(--text-sm); line-height: 1.6; margin-bottom: var(--space-md);">
        <strong>${currentLang === 'ta' ? 'சூழல்:' : 'Situation:'}</strong> ${escapeHtml(scen.situation)}
      </p>
      <p style="font-weight: 600; font-size: var(--text-sm); margin-bottom: var(--space-sm);">
        ${escapeHtml(scen.question)}
      </p>
      <div style="margin-bottom: var(--space-sm);">
        ${optionsHtml}
      </div>
      <div id="feedback_${sIndex}" class="scenario-feedback"></div>
    `;
    container.appendChild(card);
  });
}

window.checkScenario = function(sIndex, selectedIndex, correctIndex) {
  const feedbackEl = document.getElementById(`feedback_${sIndex}`);
  if (!feedbackEl || !scenariosCache[sIndex]) return;

  const scen = scenariosCache[sIndex];
  const isCorrect = selectedIndex === correctIndex;

  feedbackEl.className = 'scenario-feedback ' + (isCorrect ? 'correct' : 'incorrect');

  const titlePrefix = isCorrect 
    ? (currentLang === 'ta' ? '✅ சரியானது!' : '✅ Correct Decision!')
    : (currentLang === 'ta' ? '⚠️ கவனமாக இருங்கள் / தவறானது' : '⚠️ High Risk / Incorrect Choice');

  feedbackEl.innerHTML = `
    <strong>${titlePrefix}</strong>
    <p style="margin: 0.5rem 0 0 0;">${escapeHtml(scen.explanation)}</p>
  `;
};

function renderChecklist() {
  const container = document.getElementById('checklistItemsList');
  if (!container || !localeData.checklist_items) return;

  checklistCache = localeData.checklist_items;
  container.innerHTML = '';

  const savedStates = getChecklistSavedStates();

  checklistCache.forEach((itemText, idx) => {
    const row = document.createElement('label');
    row.className = 'checklist-item';
    const isChecked = savedStates[idx] === true;

    row.innerHTML = `
      <input type="checkbox" class="checklist-checkbox" data-index="${idx}" ${isChecked ? 'checked' : ''} onchange="onChecklistChange(${idx}, this.checked)">
      <span style="font-size: var(--text-sm); color: var(--color-text-secondary); line-height: 1.5;">${escapeHtml(itemText)}</span>
    `;
    container.appendChild(row);
  });

  updateChecklistProgress();
}

function getChecklistSavedStates() {
  try {
    const raw = localStorage.getItem('qshield_checklist_state');
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    return {};
  }
}

window.onChecklistChange = function(index, checked) {
  const states = getChecklistSavedStates();
  states[index] = checked;
  localStorage.setItem('qshield_checklist_state', JSON.stringify(states));
  updateChecklistProgress();
};

window.resetChecklist = function() {
  localStorage.removeItem('qshield_checklist_state');
  document.querySelectorAll('.checklist-checkbox').forEach(cb => {
    cb.checked = false;
  });
  updateChecklistProgress();
};

function updateChecklistProgress() {
  const total = checklistCache.length || 7;
  const states = getChecklistSavedStates();
  let verified = 0;
  for (let i = 0; i < total; i++) {
    if (states[i]) verified++;
  }

  const pct = Math.round((verified / total) * 100);
  const fill = document.getElementById('checklistProgressFill');
  const label = document.getElementById('checklistPercentage');

  if (fill) fill.style.width = `${pct}%`;
  if (label) {
    const unitText = currentLang === 'ta' ? 'சரிபார்க்கப்பட்டது' : 'Verified';
    label.textContent = `${pct}% (${verified}/${total} ${unitText})`;
  }
}

function initSearch() {
  const input = document.getElementById('guideSearchInput');
  if (!input) return;

  input.addEventListener('input', () => {
    filterGuides();
  });
}

function filterGuides() {
  const input = document.getElementById('guideSearchInput');
  const emptyState = document.getElementById('searchEmptyState');
  if (!input) return;

  const query = input.value.trim().toLowerCase();
  const cards = document.querySelectorAll('.guide-card');
  let matchedCount = 0;

  cards.forEach(card => {
    const title = card.getAttribute('data-guide-title') || '';
    const desc = card.getAttribute('data-guide-desc') || '';
    const pointsText = card.querySelector('.guide-points') ? card.querySelector('.guide-points').textContent.toLowerCase() : '';

    if (!query || title.includes(query) || desc.includes(query) || pointsText.includes(query)) {
      card.style.display = 'flex';
      matchedCount++;
    } else {
      card.style.display = 'none';
    }
  });

  if (emptyState) {
    emptyState.style.display = (matchedCount === 0 && query) ? 'block' : 'none';
  }
}

function initChecklistState() {
  // initial state loaded during renderChecklist()
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
