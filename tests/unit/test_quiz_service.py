"""
Unit tests for QShield Cyber Safety Academy: quiz service, question bank validation,
scoring engine, language parity, and progress management.
"""
import os
import json
import pytest
from app.core.quiz_service import (
    load_quiz_data, clear_quiz_cache, get_categories, CATEGORIES_META,
    get_category_questions_for_client, check_answer, evaluate_quiz_submission,
    get_performance_tier, LOCALES_DIR
)


@pytest.fixture(autouse=True)
def reset_cache():
    """Ensure quiz cache is cleared before and after each test."""
    clear_quiz_cache()
    yield
    clear_quiz_cache()


# ── 1. Dashboard / categories availability ──

class TestAcademyDashboard:

    def test_en_quiz_data_loads(self):
        data = load_quiz_data("en")
        assert isinstance(data, dict)
        assert "questions" in data
        assert len(data["questions"]) >= 36

    def test_all_six_categories_available(self):
        cats = get_categories("en")
        assert len(cats) == 6
        cat_ids = {c["id"] for c in cats}
        expected = {"qr-basics", "qr-phishing", "upi-payment", "suspicious-urls", "wifi-privacy", "redirects-safe-browsing"}
        assert cat_ids == expected

    def test_each_category_has_at_least_six_questions(self):
        cats = get_categories("en")
        for cat in cats:
            assert cat["question_count"] >= 6, f"Category '{cat['id']}' has only {cat['question_count']} questions"

    def test_at_least_36_total_questions(self):
        cats = get_categories("en")
        total = sum(c["question_count"] for c in cats)
        assert total >= 36


# ── 2. Question bank structure ──

class TestQuestionBank:

    def test_each_question_has_four_options(self):
        data = load_quiz_data("en")
        for q in data["questions"]:
            assert len(q["options"]) == 4, f"Question '{q['id']}' has {len(q['options'])} options"
            opt_ids = {o["id"] for o in q["options"]}
            assert opt_ids == {"A", "B", "C", "D"}, f"Question '{q['id']}' option IDs: {opt_ids}"

    def test_each_question_has_valid_correct_answer(self):
        data = load_quiz_data("en")
        for q in data["questions"]:
            assert q["correct_answer"] in {"A", "B", "C", "D"}, f"Question '{q['id']}' has invalid correct answer: {q['correct_answer']}"

    def test_question_ids_are_unique(self):
        data = load_quiz_data("en")
        ids = [q["id"] for q in data["questions"]]
        assert len(ids) == len(set(ids)), f"Duplicate question IDs found"

    def test_questions_have_required_fields(self):
        data = load_quiz_data("en")
        required = {"id", "category_id", "question", "options", "correct_answer", "explanation", "safety_takeaway"}
        for q in data["questions"]:
            missing = required - set(q.keys())
            assert not missing, f"Question '{q['id']}' missing fields: {missing}"

    def test_client_questions_strip_correct_answer(self):
        questions = get_category_questions_for_client("qr-basics", "en")
        assert len(questions) >= 6
        for q in questions:
            assert "correct_answer" not in q, f"Question '{q['id']}' leaks correct_answer to client"


# ── 3. Scoring ──

class TestScoring:

    def test_correct_answer_scoring(self):
        result = check_answer("q_basics_01", "B", "en")
        assert result["success"] is True
        assert result["is_correct"] is True

    def test_incorrect_answer_scoring(self):
        result = check_answer("q_basics_01", "A", "en")
        assert result["success"] is True
        assert result["is_correct"] is False
        assert result["correct_answer"] == "B"

    def test_unknown_question_returns_error(self):
        result = check_answer("q_nonexistent_999", "A", "en")
        assert result["success"] is False
        assert "QUESTION_NOT_FOUND" in result.get("error", "")

    def test_full_quiz_evaluation_all_correct(self):
        data = load_quiz_data("en")
        questions = [q for q in data["questions"] if q["category_id"] == "qr-basics"]
        answers = [{"question_id": q["id"], "selected_option_id": q["correct_answer"]} for q in questions]
        result = evaluate_quiz_submission("qr-basics", answers, "en")
        assert result["success"] is True
        assert result["correct_count"] == len(questions)
        assert result["percentage"] == 100.0
        assert result["tier_key"] == "excellent_understanding"

    def test_full_quiz_evaluation_all_incorrect(self):
        data = load_quiz_data("en")
        questions = [q for q in data["questions"] if q["category_id"] == "qr-basics"]
        # Pick wrong answers
        answers = []
        for q in questions:
            wrong = "A" if q["correct_answer"] != "A" else "B"
            answers.append({"question_id": q["id"], "selected_option_id": wrong})
        result = evaluate_quiz_submission("qr-basics", answers, "en")
        assert result["success"] is True
        assert result["correct_count"] == 0
        assert result["percentage"] == 0.0
        assert result["tier_key"] == "needs_more_practice"

    def test_duplicate_submissions_counted_once(self):
        data = load_quiz_data("en")
        questions = [q for q in data["questions"] if q["category_id"] == "qr-basics"]
        q0 = questions[0]
        # Submit same question twice (first answer counts)
        answers = [
            {"question_id": q0["id"], "selected_option_id": q0["correct_answer"]},
            {"question_id": q0["id"], "selected_option_id": "A"}  # duplicate should be ignored
        ]
        # Add rest correctly
        for q in questions[1:]:
            answers.append({"question_id": q["id"], "selected_option_id": q["correct_answer"]})
        result = evaluate_quiz_submission("qr-basics", answers, "en")
        assert result["correct_count"] == len(questions)

    def test_percentage_calculation(self):
        data = load_quiz_data("en")
        questions = [q for q in data["questions"] if q["category_id"] == "qr-basics"]
        total = len(questions)
        # Answer half correctly
        answers = []
        for i, q in enumerate(questions):
            if i < total // 2:
                answers.append({"question_id": q["id"], "selected_option_id": q["correct_answer"]})
            else:
                wrong = "A" if q["correct_answer"] != "A" else "B"
                answers.append({"question_id": q["id"], "selected_option_id": wrong})
        result = evaluate_quiz_submission("qr-basics", answers, "en")
        expected_pct = round((total // 2) / total * 100, 1)
        assert result["percentage"] == expected_pct

    def test_empty_category_returns_error(self):
        result = evaluate_quiz_submission("nonexistent-category", [], "en")
        assert result["success"] is False
        assert "CATEGORY_EMPTY" in result.get("error", "")


# ── 4. Performance tiers ──

class TestPerformanceTiers:

    def test_excellent_tier(self):
        tier = get_performance_tier(90.0, "en")
        assert tier["tier_key"] == "excellent_understanding"
        assert tier["label"] == "Excellent Understanding"

    def test_good_tier(self):
        tier = get_performance_tier(70.0, "en")
        assert tier["tier_key"] == "good_progress"

    def test_needs_practice_tier(self):
        tier = get_performance_tier(40.0, "en")
        assert tier["tier_key"] == "needs_more_practice"

    def test_boundary_85_is_excellent(self):
        tier = get_performance_tier(85.0, "en")
        assert tier["tier_key"] == "excellent_understanding"

    def test_boundary_60_is_good(self):
        tier = get_performance_tier(60.0, "en")
        assert tier["tier_key"] == "good_progress"

    def test_boundary_59_is_needs_practice(self):
        tier = get_performance_tier(59.0, "en")
        assert tier["tier_key"] == "needs_more_practice"

    def test_tamil_label(self):
        tier = get_performance_tier(95.0, "ta")
        assert "சிறந்த" in tier["label"]


# ── 5. Language parity ──

class TestLanguageParity:

    def test_ta_quiz_file_exists(self):
        path = os.path.join(LOCALES_DIR, "ta.json")
        assert os.path.exists(path), "Tamil quiz file (quiz_data/ta.json) not found"

    def test_ta_and_en_same_question_ids(self):
        en_data = load_quiz_data("en")
        clear_quiz_cache()
        ta_data = load_quiz_data("ta")
        en_ids = sorted([q["id"] for q in en_data["questions"]])
        ta_ids = sorted([q["id"] for q in ta_data["questions"]])
        assert en_ids == ta_ids

    def test_ta_and_en_same_correct_answers(self):
        en_data = load_quiz_data("en")
        clear_quiz_cache()
        ta_data = load_quiz_data("ta")
        en_answers = {q["id"]: q["correct_answer"] for q in en_data["questions"]}
        ta_answers = {q["id"]: q["correct_answer"] for q in ta_data["questions"]}
        assert en_answers == ta_answers

    def test_explanations_available_in_both_languages(self):
        en_data = load_quiz_data("en")
        clear_quiz_cache()
        ta_data = load_quiz_data("ta")
        for eq in en_data["questions"]:
            tq = next((q for q in ta_data["questions"] if q["id"] == eq["id"]), None)
            assert tq is not None, f"Tamil missing question {eq['id']}"
            assert len(tq.get("explanation", "")) > 5, f"Tamil explanation too short for {eq['id']}"
            assert len(tq.get("safety_takeaway", "")) > 3, f"Tamil takeaway too short for {eq['id']}"

    def test_language_fallback_to_english(self):
        """If 'fr' is requested, it should fall back to English data."""
        data = load_quiz_data("fr")
        assert data["language"] == "en"

    def test_check_answer_correct_in_tamil(self):
        result = check_answer("q_basics_01", "B", "ta")
        assert result["success"] is True
        assert result["is_correct"] is True

    def test_language_switching_preserves_question_structure(self):
        en_q = get_category_questions_for_client("qr-basics", "en")
        clear_quiz_cache()
        ta_q = get_category_questions_for_client("qr-basics", "ta")
        assert len(en_q) == len(ta_q)
        for eq, tq in zip(sorted(en_q, key=lambda x: x["id"]), sorted(ta_q, key=lambda x: x["id"])):
            assert eq["id"] == tq["id"]
            assert len(eq["options"]) == len(tq["options"])


# ── 6. Feedback and explanations ──

class TestFeedback:

    def test_correct_feedback_message(self):
        result = check_answer("q_upi_01", "B", "en")
        assert result["is_correct"] is True
        assert "Correct" in result["feedback_message"]

    def test_incorrect_feedback_supportive(self):
        result = check_answer("q_upi_01", "A", "en")
        assert result["is_correct"] is False
        assert "Good try" in result["feedback_message"]

    def test_explanation_present(self):
        result = check_answer("q_upi_01", "A", "en")
        assert len(result["explanation"]) > 10

    def test_safety_takeaway_present(self):
        result = check_answer("q_upi_01", "B", "en")
        assert len(result["safety_takeaway"]) > 5

    def test_related_guide_id_present(self):
        result = check_answer("q_upi_01", "B", "en")
        assert result["related_guide_id"] != ""


# ── 7. Progress bar and summary ──

class TestQuizSummary:

    def _get_full_correct_answers(self, cat_id, lang="en"):
        data = load_quiz_data(lang)
        questions = [q for q in data["questions"] if q["category_id"] == cat_id]
        return [{"question_id": q["id"], "selected_option_id": q["correct_answer"]} for q in questions]

    def test_summary_reflects_actual_answers(self):
        answers = self._get_full_correct_answers("qr-phishing")
        result = evaluate_quiz_submission("qr-phishing", answers, "en")
        assert result["percentage"] == 100.0
        assert result["incorrect_count"] == 0

    def test_incorrect_review_present(self):
        data = load_quiz_data("en")
        questions = [q for q in data["questions"] if q["category_id"] == "qr-phishing"]
        # Answer first question wrong, rest correct
        answers = []
        for i, q in enumerate(questions):
            if i == 0:
                wrong = "A" if q["correct_answer"] != "A" else "C"
                answers.append({"question_id": q["id"], "selected_option_id": wrong})
            else:
                answers.append({"question_id": q["id"], "selected_option_id": q["correct_answer"]})
        result = evaluate_quiz_submission("qr-phishing", answers, "en")
        assert result["incorrect_count"] == 1
        assert len(result["incorrect_reviews"]) == 1
        review = result["incorrect_reviews"][0]
        assert review["question_id"] == questions[0]["id"]
        assert review["selected_option_id"] != review["correct_option_id"]

    def test_retry_resets_attempt(self):
        """A second call with the same category should produce independent results."""
        answers_correct = self._get_full_correct_answers("qr-basics")
        r1 = evaluate_quiz_submission("qr-basics", answers_correct, "en")
        assert r1["percentage"] == 100.0
        # Second attempt all wrong
        data = load_quiz_data("en")
        questions = [q for q in data["questions"] if q["category_id"] == "qr-basics"]
        answers_wrong = [{"question_id": q["id"], "selected_option_id": "A" if q["correct_answer"] != "A" else "C"} for q in questions]
        r2 = evaluate_quiz_submission("qr-basics", answers_wrong, "en")
        assert r2["correct_count"] == 0
        assert r2["percentage"] == 0.0
