/**
 * QShield Cyber Safety Academy — Client-Side Quiz Controller
 * Handles category browsing, server-side answer checking, scoring,
 * review mode, localStorage progress, and bilingual EN/TA switching.
 */

/* ── State ── */
let acLang = localStorage.getItem('qshield_academy_lang') || 'en';
let acCategories = [];
let acQuizQuestions = [];
let acCurrentIdx = 0;
let acScore = 0;
let acAnswers = []; // { question_id, selected_option_id, is_correct }
let acAnswered = false; // has current question been submitted
let acCurrentCatId = '';
let acCurrentCatTitle = '';
let acStartTime = null;
let acSummaryData = null;

const STORAGE_KEY = 'qshield_academy_progress';

/* ── Localized Strings ── */
const L = {
  en: {
    heroBadge: 'Interactive Cybersecurity Learning',
    heroTitle: 'QShield Cyber Safety Academy',
    heroSub: 'Learn Smart. Scan Safe. Stay Protected.',
    progressTitle: 'Your Learning Progress',
    totalQ: 'Total Questions',
    catsDone: 'Categories Completed',
    bestScore: 'Best Score',
    totalAtt: 'Total Attempts',
    awareness: 'Back to Awareness Centre',
    resetBtn: 'Reset Learning Progress',
    localNotice: 'Progress is stored locally in your browser. Clearing browser data or switching devices will reset your progress.',
    catHeading: 'Quiz Categories',
    startQuiz: 'Start Quiz',
    questions: 'questions',
    langs: 'English & தமிழ்',
    emptyTitle: 'Welcome to the Academy!',
    emptyDesc: 'Choose a category above to start your first quiz and begin learning.',
    exitQuiz: '✕ Exit Quiz',
    questionOf: 'Question {n} of {t}',
    scoreLabel: 'Score: {c}/{a}',
    submitAnswer: 'Submit Answer',
    nextQuestion: 'Next Question →',
    viewResults: 'View Results',
    quizComplete: 'Quiz Complete',
    correct: 'Correct',
    incorrect: 'Incorrect',
    total: 'Total',
    time: 'Time',
    topicsCorrectTitle: '✓ Topics Answered Correctly',
    topicsPracticeTitle: '✗ Topics Needing Practice',
    reviewTitle: 'Review Incorrect Answers',
    retryBtn: '🔁 Retry Quiz',
    backBtn: '← Back to Academy',
    awarenessBtn: '📖 Awareness Centre',
    yourAnswer: 'Your answer',
    correctAnswer: 'Correct answer',
    explanation: 'Explanation',
    safetyTip: 'Safety Takeaway',
    learnMore: '→ Learn more in Awareness Centre',
    resetModalTitle: 'Reset Learning Progress?',
    resetModalDesc: 'This will permanently delete all quiz scores, attempts, and progress from your browser. This action cannot be undone.',
    confirmReset: 'Yes, Reset Everything',
    cancel: 'Cancel',
    bestLabel: 'Best',
    lastLabel: 'Last',
    attemptsLabel: 'attempts',
    suggestedNext: '★ Suggested',
    selectAnswer: 'Please select an answer first.',
    correctFeedback: 'Correct! Remember to verify the destination.',
    incorrectFeedback: "Good try — here's what to look for.",
    minutes: 'min',
    seconds: 'sec'
  },
  ta: {
    heroBadge: 'ஊடாடும் இணையப் பாதுகாப்பு கற்றல்',
    heroTitle: 'QShield சைபர் பாதுகாப்பு அகாடமி',
    heroSub: 'புத்திசாலித்தனமாகக் கற்றுக் கொள்ளுங்கள். பாதுகாப்பாக ஸ்கேன் செய்யுங்கள்.',
    progressTitle: 'உங்கள் கற்றல் முன்னேற்றம்',
    totalQ: 'மொத்த கேள்விகள்',
    catsDone: 'முடிக்கப்பட்ட பிரிவுகள்',
    bestScore: 'சிறந்த மதிப்பெண்',
    totalAtt: 'மொத்த முயற்சிகள்',
    awareness: 'விழிப்புணர்வு மையத்திற்கு',
    resetBtn: 'முன்னேற்றத்தை மீட்டமைக்க',
    localNotice: 'முன்னேற்றம் உங்கள் உலாவியில் உள்ளூரில் சேமிக்கப்படும். உலாவி தரவை அழிப்பது அல்லது சாதனம் மாற்றுவது முன்னேற்றத்தை மீட்டமைக்கும்.',
    catHeading: 'வினாடி வினா பிரிவுகள்',
    startQuiz: 'வினாடி வினா தொடங்கு',
    questions: 'கேள்விகள்',
    langs: 'English & தமிழ்',
    emptyTitle: 'அகாடமிக்கு வரவேற்கிறோம்!',
    emptyDesc: 'உங்கள் முதல் வினாடி வினாவைத் தொடங்க மேலே ஒரு பிரிவைத் தேர்ந்தெடுக்கவும்.',
    exitQuiz: '✕ வெளியேறு',
    questionOf: 'கேள்வி {n} / {t}',
    scoreLabel: 'மதிப்பெண்: {c}/{a}',
    submitAnswer: 'பதிலை சமர்ப்பிக்கவும்',
    nextQuestion: 'அடுத்த கேள்வி →',
    viewResults: 'முடிவுகளைக் காண',
    quizComplete: 'வினாடி வினா முடிந்தது',
    correct: 'சரி',
    incorrect: 'தவறு',
    total: 'மொத்தம்',
    time: 'நேரம்',
    topicsCorrectTitle: '✓ சரியாக பதிலளித்த தலைப்புகள்',
    topicsPracticeTitle: '✗ கூடுதல் பயிற்சி தேவைப்படும் தலைப்புகள்',
    reviewTitle: 'தவறான பதில்களை மதிப்பாய்வு செய்யுங்கள்',
    retryBtn: '🔁 மீண்டும் முயற்சிக்கவும்',
    backBtn: '← அகாடமிக்குத் திரும்பு',
    awarenessBtn: '📖 விழிப்புணர்வு மையம்',
    yourAnswer: 'உங்கள் பதில்',
    correctAnswer: 'சரியான பதில்',
    explanation: 'விளக்கம்',
    safetyTip: 'பாதுகாப்பு குறிப்பு',
    learnMore: '→ விழிப்புணர்வு மையத்தில் மேலும் அறிக',
    resetModalTitle: 'கற்றல் முன்னேற்றத்தை மீட்டமைக்கவா?',
    resetModalDesc: 'இது அனைத்து வினாடி வினா மதிப்பெண்கள், முயற்சிகள் மற்றும் முன்னேற்றத்தை நிரந்தரமாக நீக்கும். இதை மாற்ற இயலாது.',
    confirmReset: 'ஆம், அனைத்தையும் மீட்டமைக்கவும்',
    cancel: 'ரத்துசெய்',
    bestLabel: 'சிறந்தது',
    lastLabel: 'கடைசி',
    attemptsLabel: 'முயற்சிகள்',
    suggestedNext: '★ பரிந்துரைக்கப்பட்டது',
    selectAnswer: 'முதலில் ஒரு பதிலைத் தேர்ந்தெடுக்கவும்.',
    correctFeedback: 'சரியானது! இலக்கை எப்போதும் சரிபார்க்கவும்.',
    incorrectFeedback: 'நல்ல முயற்சி — நீங்கள் கவனிக்க வேண்டியது இங்கே உள்ளது.',
    minutes: 'நிமிடம்',
    seconds: 'விநாடி'
  }
};

function t(key) { return (L[acLang] && L[acLang][key]) || L.en[key] || key; }

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  acSetLang(acLang);
});

/* ── Language ── */
window.acSetLang = function(lang) {
  acLang = (lang === 'ta') ? 'ta' : 'en';
  localStorage.setItem('qshield_academy_lang', acLang);
  document.getElementById('acLangEn').classList.toggle('active', acLang === 'en');
  document.getElementById('acLangTa').classList.toggle('active', acLang === 'ta');
  applyAcLabels();
  loadCategories();
};

function applyAcLabels() {
  const m = {
    acHeroBadge: 'heroBadge', acHeroTitle: 'heroTitle', acHeroSubtitle: 'heroSub',
    acProgressTitle: 'progressTitle', statTotalLabel: 'totalQ', statCatsLabel: 'catsDone',
    statBestLabel: 'bestScore', statAttLabel: 'totalAtt', acAwarenessLink: 'awareness',
    acResetBtn: 'resetBtn', acLocalNotice: 'localNotice', acCatHeading: 'catHeading',
    acEmptyTitle: 'emptyTitle', acEmptyDesc: 'emptyDesc', quizExitBtn: 'exitQuiz',
    quizSubmitBtn: 'submitAnswer', quizNextBtn: 'nextQuestion', quizFinishBtn: 'viewResults',
    summaryTitle: 'quizComplete', sumCorrectLbl: 'correct', sumIncorrectLbl: 'incorrect',
    sumTotalLbl: 'total', sumTimeLbl: 'time', sumTopicsCorrectTitle: 'topicsCorrectTitle',
    sumTopicsPracticeTitle: 'topicsPracticeTitle', sumReviewTitle: 'reviewTitle',
    sumRetryBtn: 'retryBtn', sumBackBtn: 'backBtn', sumAwarenessBtn: 'awarenessBtn',
    resetModalTitle: 'resetModalTitle', resetModalDesc: 'resetModalDesc',
    resetConfirmBtn: 'confirmReset', resetCancelBtn: 'cancel'
  };
  for (const [elId, key] of Object.entries(m)) {
    const el = document.getElementById(elId);
    if (el) el.textContent = t(key);
  }
}

/* ── Categories & Dashboard ── */
async function loadCategories() {
  try {
    const res = await fetch(`/api/quiz/categories?lang=${acLang}`);
    const json = await res.json();
    if (json.success) {
      acCategories = json.categories;
      renderCategories();
      updateProgressDashboard();
    }
  } catch (e) {
    console.error('Failed to load categories:', e);
  }
}

function renderCategories() {
  const grid = document.getElementById('categoriesGrid');
  if (!grid) return;
  grid.innerHTML = '';
  const progress = getProgress();

  // Find suggested category (lowest best score or not attempted)
  let suggestedId = '';
  let lowestScore = 101;
  for (const cat of acCategories) {
    const p = progress[cat.id];
    if (!p || p.attempts === 0) { suggestedId = cat.id; break; }
    if (p.best_pct < lowestScore) { lowestScore = p.best_pct; suggestedId = cat.id; }
  }

  for (const cat of acCategories) {
    const card = document.createElement('div');
    card.className = 'cat-card';
    const p = progress[cat.id];
    let progressHtml = '';
    if (p && p.attempts > 0) {
      progressHtml = `<div style="font-size:0.78rem; color:var(--color-teal); font-weight:600;">${t('bestLabel')}: ${p.best_pct}% · ${t('lastLabel')}: ${p.last_pct}% · ${p.attempts} ${t('attemptsLabel')}</div>`;
    }
    const isSuggested = (cat.id === suggestedId);
    const sugBadge = isSuggested ? `<span style="background:#22c55e; color:#fff; font-size:0.7rem; padding:0.1rem 0.4rem; border-radius:var(--radius-sm); font-weight:700;">${t('suggestedNext')}</span>` : '';

    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <div class="hero-badge" style="font-size:0.72rem;">${escHtml(cat.id.replace(/-/g,' ').toUpperCase())}</div>
        ${sugBadge}
      </div>
      <h3 style="font-size:1.15rem; margin:0;">${escHtml(cat.title)}</h3>
      <p style="color:var(--color-text-secondary); font-size:var(--text-sm); line-height:1.5; margin:0;">${escHtml(cat.description)}</p>
      <div class="cat-meta">
        <span class="cat-meta-tag">${cat.question_count} ${t('questions')}</span>
        <span class="cat-meta-tag">${t('langs')}</span>
      </div>
      ${progressHtml}
      <button type="button" class="btn btn-primary" style="margin-top:auto; align-self:flex-start;" onclick="acStartQuiz('${cat.id}','${escHtml(cat.title)}')">${t('startQuiz')}</button>
    `;
    grid.appendChild(card);
  }
}

function updateProgressDashboard() {
  const progress = getProgress();
  const totalQ = acCategories.reduce((s,c) => s + c.question_count, 0);
  let catsDone = 0, bestPct = -1, totalAttempts = 0;

  for (const cat of acCategories) {
    const p = progress[cat.id];
    if (p && p.attempts > 0) {
      totalAttempts += p.attempts;
      if (p.best_pct > bestPct) bestPct = p.best_pct;
      catsDone++;
    }
  }

  document.getElementById('statTotalQ').textContent = totalQ;
  document.getElementById('statCatsDone').textContent = catsDone;
  document.getElementById('statBestPct').textContent = bestPct >= 0 ? bestPct + '%' : '—';
  document.getElementById('statAttempts').textContent = totalAttempts;
}

/* ── Quiz Flow ── */
window.acStartQuiz = async function(catId, catTitle) {
  acCurrentCatId = catId;
  acCurrentCatTitle = catTitle;
  acCurrentIdx = 0;
  acScore = 0;
  acAnswers = [];
  acAnswered = false;
  acStartTime = Date.now();

  try {
    const res = await fetch('/api/quiz/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ category_id: catId, lang: acLang })
    });
    const json = await res.json();
    if (json.success && json.questions.length > 0) {
      acQuizQuestions = json.questions;
      showView('quiz');
      renderQuestion();
    } else {
      alert(json.message || 'No questions available.');
    }
  } catch (e) {
    console.error('Failed to start quiz:', e);
  }
};

function renderQuestion() {
  const q = acQuizQuestions[acCurrentIdx];
  if (!q) return;

  acAnswered = false;
  document.getElementById('quizCatBadge').textContent = acCurrentCatTitle;
  document.getElementById('quizTitle').textContent = acCurrentCatTitle;

  const total = acQuizQuestions.length;
  const answered = acAnswers.length;
  document.getElementById('quizProgressLabel').textContent = t('questionOf').replace('{n}', acCurrentIdx + 1).replace('{t}', total);
  document.getElementById('quizScoreLabel').textContent = t('scoreLabel').replace('{c}', acScore).replace('{a}', answered);

  const pct = Math.round(((acCurrentIdx) / total) * 100);
  const bar = document.getElementById('quizProgressFill');
  bar.style.width = pct + '%';
  document.getElementById('quizProgressBarWrap').setAttribute('aria-valuenow', pct);

  document.getElementById('quizDiffBadge').textContent = q.difficulty || 'beginner';
  document.getElementById('quizQuestionText').textContent = q.question;

  // Render options
  const container = document.getElementById('quizOptionsContainer');
  container.innerHTML = '';
  (q.options || []).forEach(opt => {
    const label = document.createElement('div');
    label.className = 'quiz-option-label';
    label.setAttribute('role', 'radio');
    label.setAttribute('aria-checked', 'false');
    label.setAttribute('tabindex', '0');
    label.dataset.optionId = opt.id;
    label.innerHTML = `<div class="quiz-option-marker">${escHtml(opt.id)}</div><span style="font-size:var(--text-sm); line-height:1.5;">${escHtml(opt.text)}</span>`;
    label.addEventListener('click', () => selectOption(opt.id));
    label.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectOption(opt.id); } });
    container.appendChild(label);
  });

  // Reset UI
  document.getElementById('quizFeedback').className = 'quiz-feedback-box';
  document.getElementById('quizFeedback').innerHTML = '';
  document.getElementById('quizSubmitBtn').style.display = 'inline-flex';
  document.getElementById('quizSubmitBtn').disabled = true;
  document.getElementById('quizNextBtn').style.display = 'none';
  document.getElementById('quizFinishBtn').style.display = 'none';
}

let selectedOptionId = null;

function selectOption(optId) {
  if (acAnswered) return;
  selectedOptionId = optId;
  document.querySelectorAll('#quizOptionsContainer .quiz-option-label').forEach(el => {
    el.classList.toggle('selected', el.dataset.optionId === optId);
    el.setAttribute('aria-checked', el.dataset.optionId === optId ? 'true' : 'false');
  });
  document.getElementById('quizSubmitBtn').disabled = false;
}

window.acSubmitAnswer = async function() {
  if (acAnswered || !selectedOptionId) return;
  acAnswered = true;

  const q = acQuizQuestions[acCurrentIdx];
  document.getElementById('quizSubmitBtn').disabled = true;

  try {
    const res = await fetch('/api/quiz/check-answer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question_id: q.id, selected_option_id: selectedOptionId, lang: acLang })
    });
    const json = await res.json();

    if (json.success) {
      const isCorrect = json.is_correct;
      if (isCorrect) acScore++;

      acAnswers.push({
        question_id: q.id,
        selected_option_id: selectedOptionId,
        is_correct: isCorrect
      });

      // Update score label
      document.getElementById('quizScoreLabel').textContent = t('scoreLabel').replace('{c}', acScore).replace('{a}', acAnswers.length);

      // Reveal correct/incorrect on options
      document.querySelectorAll('#quizOptionsContainer .quiz-option-label').forEach(el => {
        el.classList.add('disabled');
        if (el.dataset.optionId === json.correct_answer) {
          el.classList.add('correct-reveal');
        } else if (el.dataset.optionId === selectedOptionId && !isCorrect) {
          el.classList.add('incorrect-reveal');
        }
      });

      // Show feedback
      const fb = document.getElementById('quizFeedback');
      const guideLink = json.related_guide_id ? `<br><a href="/awareness#${json.related_guide_id}" style="color:inherit; font-weight:600;">${t('learnMore')}</a>` : '';
      fb.className = 'quiz-feedback-box ' + (isCorrect ? 'correct' : 'incorrect');
      fb.innerHTML = `
        <strong>${json.feedback_message}</strong>
        <p style="margin:0.5rem 0 0;"><strong>${t('explanation')}:</strong> ${escHtml(json.explanation)}</p>
        <p style="margin:0.3rem 0 0;"><strong>${t('safetyTip')}:</strong> ${escHtml(json.safety_takeaway)}</p>
        ${guideLink}
      `;

      // Show next/finish button
      document.getElementById('quizSubmitBtn').style.display = 'none';
      if (acCurrentIdx < acQuizQuestions.length - 1) {
        document.getElementById('quizNextBtn').style.display = 'inline-flex';
      } else {
        document.getElementById('quizFinishBtn').style.display = 'inline-flex';
      }
    }
  } catch (e) {
    console.error('Answer check failed:', e);
    acAnswered = false;
    document.getElementById('quizSubmitBtn').disabled = false;
  }
};

window.acNextQuestion = function() {
  acCurrentIdx++;
  selectedOptionId = null;
  renderQuestion();
};

window.acExitQuiz = function() {
  // Don't save incomplete results
  showView('dashboard');
  loadCategories();
};

/* ── Finish & Summary ── */
window.acFinishQuiz = async function() {
  const elapsed = Date.now() - acStartTime;
  try {
    const res = await fetch('/api/quiz/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        category_id: acCurrentCatId,
        answers: acAnswers.map(a => ({ question_id: a.question_id, selected_option_id: a.selected_option_id })),
        lang: acLang
      })
    });
    const json = await res.json();
    if (json.success) {
      acSummaryData = json;
      acSummaryData._elapsed = elapsed;
      saveAttempt(acCurrentCatId, json.percentage);
      renderSummary();
      showView('summary');
    }
  } catch (e) {
    console.error('Evaluation failed:', e);
  }
};

function renderSummary() {
  const d = acSummaryData;
  if (!d) return;

  document.getElementById('summaryCatName').textContent = acCurrentCatTitle;

  // Score ring
  const ring = document.getElementById('summaryScoreRing');
  ring.textContent = d.percentage + '%';
  if (d.percentage >= 85) {
    ring.style.borderColor = '#22c55e'; ring.style.color = '#22c55e';
  } else if (d.percentage >= 60) {
    ring.style.borderColor = '#f59e0b'; ring.style.color = '#f59e0b';
  } else {
    ring.style.borderColor = '#ef4444'; ring.style.color = '#ef4444';
  }

  document.getElementById('summaryPerfLabel').textContent = d.performance_label;
  document.getElementById('sumCorrect').textContent = d.correct_count;
  document.getElementById('sumIncorrect').textContent = d.incorrect_count;
  document.getElementById('sumTotal').textContent = d.total_questions;

  // Time
  const secs = Math.round((d._elapsed || 0) / 1000);
  const mins = Math.floor(secs / 60);
  const remSecs = secs % 60;
  document.getElementById('sumTimeTaken').textContent = mins > 0 ? `${mins} ${t('minutes')} ${remSecs} ${t('seconds')}` : `${remSecs} ${t('seconds')}`;

  document.getElementById('summarySummaryText').textContent = d.summary_text;

  // Topics
  const tcEl = document.getElementById('summaryTopicsCorrect');
  const tpEl = document.getElementById('summaryTopicsPractice');
  if (d.topics_correct && d.topics_correct.length > 0) {
    tcEl.style.display = 'block';
    document.getElementById('sumTopicsCorrectList').innerHTML = d.topics_correct.map(t => `<li>${escHtml(t)}</li>`).join('');
  } else { tcEl.style.display = 'none'; }
  if (d.topics_needing_practice && d.topics_needing_practice.length > 0) {
    tpEl.style.display = 'block';
    document.getElementById('sumTopicsPracticeList').innerHTML = d.topics_needing_practice.map(t => `<li>${escHtml(t)}</li>`).join('');
  } else { tpEl.style.display = 'none'; }

  // Review incorrect
  const reviewSection = document.getElementById('summaryReviewSection');
  const reviewList = document.getElementById('summaryReviewList');
  if (d.incorrect_reviews && d.incorrect_reviews.length > 0) {
    reviewSection.style.display = 'block';
    reviewList.innerHTML = '';
    d.incorrect_reviews.forEach(r => {
      const userOptText = (r.options || []).find(o => o.id === r.selected_option_id);
      const correctOptText = (r.options || []).find(o => o.id === r.correct_option_id);
      const guideLink = r.related_guide_id ? `<a href="/awareness#${r.related_guide_id}" style="color:var(--color-teal); font-weight:600; font-size:0.85rem;">${t('learnMore')}</a>` : '';

      const item = document.createElement('div');
      item.className = 'review-item';
      item.innerHTML = `
        <h4 style="font-size:1rem; margin-bottom:var(--space-sm);">${escHtml(r.question_text)}</h4>
        <p style="font-size:var(--text-sm); color:#ef4444; margin-bottom:0.3rem;"><strong>${t('yourAnswer')}:</strong> ${escHtml(userOptText ? userOptText.text : r.selected_option_id || '—')}</p>
        <p style="font-size:var(--text-sm); color:#22c55e; margin-bottom:0.3rem;"><strong>${t('correctAnswer')}:</strong> ${escHtml(correctOptText ? correctOptText.text : r.correct_option_id)}</p>
        <p style="font-size:var(--text-sm); margin-bottom:0.3rem;"><strong>${t('explanation')}:</strong> ${escHtml(r.explanation)}</p>
        <p style="font-size:var(--text-sm); margin-bottom:0.3rem;"><strong>${t('safetyTip')}:</strong> ${escHtml(r.safety_takeaway)}</p>
        ${guideLink}
      `;
      reviewList.appendChild(item);
    });
  } else { reviewSection.style.display = 'none'; }
}

window.acRetryQuiz = function() {
  acStartQuiz(acCurrentCatId, acCurrentCatTitle);
};

window.acBackToDashboard = function() {
  showView('dashboard');
  loadCategories();
};

/* ── View Switching ── */
function showView(view) {
  document.getElementById('academyDashboard').style.display = (view === 'dashboard') ? 'block' : 'none';
  document.getElementById('quizContainer').style.display = (view === 'quiz') ? 'block' : 'none';
  document.getElementById('summaryContainer').style.display = (view === 'summary') ? 'block' : 'none';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ── Progress (localStorage) ── */
function getProgress() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch (e) { return {}; }
}

function saveAttempt(catId, pct) {
  const progress = getProgress();
  if (!progress[catId]) {
    progress[catId] = { attempts: 0, best_pct: 0, last_pct: 0 };
  }
  progress[catId].attempts++;
  progress[catId].last_pct = pct;
  if (pct > progress[catId].best_pct) {
    progress[catId].best_pct = pct;
  }
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
  } catch (e) {
    console.warn('Could not save progress:', e);
  }
}

window.acResetProgress = function() {
  const modal = document.getElementById('resetModal');
  modal.style.display = 'flex';
};

window.acConfirmReset = function() {
  localStorage.removeItem(STORAGE_KEY);
  document.getElementById('resetModal').style.display = 'none';
  loadCategories();
};

window.acCancelReset = function() {
  document.getElementById('resetModal').style.display = 'none';
};

/* ── Utility ── */
function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
