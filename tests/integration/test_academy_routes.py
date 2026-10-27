"""
Integration tests for QShield Cyber Safety Academy routes and quiz API endpoints.
"""
import pytest
from app import create_app
from config import TestingConfig


@pytest.fixture
def client():
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client


class TestAcademyPage:

    def test_academy_page_loads(self, client):
        response = client.get('/academy')
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'Cyber Safety Academy' in html
        assert 'academyDashboard' in html
        assert 'quizContainer' in html
        assert 'summaryContainer' in html
        assert 'acLangEn' in html
        assert 'acLangTa' in html


class TestQuizCategoriesAPI:

    def test_get_categories_en(self, client):
        response = client.get('/api/quiz/categories?lang=en')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert len(data['categories']) == 6
        assert data['total_questions'] >= 36

    def test_get_categories_ta(self, client):
        response = client.get('/api/quiz/categories?lang=ta')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert len(data['categories']) == 6
        # Tamil titles should contain Tamil chars
        for cat in data['categories']:
            # At least one character in Tamil Unicode range
            has_tamil = any('\u0b80' <= c <= '\u0bff' for c in cat['title'])
            assert has_tamil, f"Category '{cat['id']}' title lacks Tamil characters"


class TestQuizStartAPI:

    def test_start_quiz_valid_category(self, client):
        response = client.post('/api/quiz/start',
            json={"category_id": "qr-basics", "lang": "en"},
            content_type='application/json')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['total_questions'] >= 6
        # Verify no correct_answer leaks
        for q in data['questions']:
            assert 'correct_answer' not in q

    def test_start_quiz_missing_category(self, client):
        response = client.post('/api/quiz/start',
            json={},
            content_type='application/json')
        assert response.status_code == 400

    def test_start_quiz_invalid_category(self, client):
        response = client.post('/api/quiz/start',
            json={"category_id": "nonexistent-cat", "lang": "en"},
            content_type='application/json')
        assert response.status_code == 404


class TestCheckAnswerAPI:

    def test_check_correct_answer(self, client):
        response = client.post('/api/quiz/check-answer',
            json={"question_id": "q_basics_01", "selected_option_id": "B", "lang": "en"},
            content_type='application/json')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['is_correct'] is True
        assert data['correct_answer'] == "B"
        assert len(data['explanation']) > 5

    def test_check_incorrect_answer(self, client):
        response = client.post('/api/quiz/check-answer',
            json={"question_id": "q_basics_01", "selected_option_id": "A", "lang": "en"},
            content_type='application/json')
        assert response.status_code == 200
        data = response.get_json()
        assert data['is_correct'] is False
        assert data['correct_answer'] == "B"

    def test_check_answer_nonexistent_question(self, client):
        response = client.post('/api/quiz/check-answer',
            json={"question_id": "q_fake_999", "selected_option_id": "A", "lang": "en"},
            content_type='application/json')
        assert response.status_code == 404

    def test_check_answer_missing_fields(self, client):
        response = client.post('/api/quiz/check-answer',
            json={"question_id": "q_basics_01"},
            content_type='application/json')
        assert response.status_code == 400


class TestEvaluateAPI:

    def test_evaluate_all_correct(self, client):
        # Get question data to build all-correct submission
        start_resp = client.post('/api/quiz/start',
            json={"category_id": "qr-basics", "lang": "en"},
            content_type='application/json')
        questions = start_resp.get_json()["questions"]

        # Check each answer server-side to get correct IDs
        answers = []
        for q in questions:
            check = client.post('/api/quiz/check-answer',
                json={"question_id": q["id"], "selected_option_id": "A", "lang": "en"},
                content_type='application/json')
            correct_id = check.get_json()["correct_answer"]
            answers.append({"question_id": q["id"], "selected_option_id": correct_id})

        response = client.post('/api/quiz/evaluate',
            json={"category_id": "qr-basics", "answers": answers, "lang": "en"},
            content_type='application/json')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['percentage'] == 100.0
        assert data['correct_count'] == len(questions)

    def test_evaluate_empty_answers(self, client):
        response = client.post('/api/quiz/evaluate',
            json={"category_id": "qr-basics", "answers": [], "lang": "en"},
            content_type='application/json')
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['correct_count'] == 0
        assert data['percentage'] == 0.0

    def test_evaluate_invalid_category(self, client):
        response = client.post('/api/quiz/evaluate',
            json={"category_id": "fake-cat", "answers": [], "lang": "en"},
            content_type='application/json')
        assert response.status_code == 404

    def test_evaluate_missing_category(self, client):
        response = client.post('/api/quiz/evaluate',
            json={"answers": []},
            content_type='application/json')
        assert response.status_code == 400


class TestExistingFeaturesIntact:

    def test_scanner_page_still_loads(self, client):
        response = client.get('/scanner')
        assert response.status_code == 200

    def test_awareness_page_still_loads(self, client):
        response = client.get('/awareness')
        assert response.status_code == 200

    def test_home_page_still_loads(self, client):
        response = client.get('/')
        assert response.status_code == 200

    def test_locale_api_still_works(self, client):
        response = client.get('/api/locale/en')
        assert response.status_code == 200
