"""
Core Quiz Manager and Evaluation Service for QShield Cyber Safety Academy.
Loads and validates question banks (English and Tamil), strips answers for safe client delivery,
scores submitted answers, and generates performance summaries and labels.
"""
import os
import json
from typing import Dict, Any, List, Optional, Tuple

LOCALES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "quiz_data")

# Performance evaluation thresholds (percentage based)
PERFORMANCE_TIERS = [
    (85, 100, "Excellent Understanding", "சிறந்த புரிதல்", "bg-success"),
    (60, 84, "Good Progress", "நல்ல முன்னேற்றம்", "bg-warning"),
    (0, 59, "Needs More Practice", "கூடுதல் பயிற்சி தேவை", "bg-danger")
]

CATEGORIES_META = [
    {
        "id": "qr-basics",
        "title_en": "QR Code Safety Basics",
        "title_ta": "QR குறியீடு பாதுகாப்பு அடிப்படைகள்",
        "desc_en": "Learn the mechanics of 2D barcodes, physical sticker overlays, and safe optical preview practices.",
        "desc_ta": "2D பார்கோடு செயல்பாடுகள், போலி ஸ்டிக்கர் ஒட்டுதல்கள் மற்றும் பாதுகாப்பான முன்னோட்ட முறைகளைக் கற்றுக்கொள்ளுங்கள்.",
        "guide_id": "qr-basics"
    },
    {
        "id": "qr-phishing",
        "title_en": "QR Phishing & Fake Login Pages",
        "title_ta": "QR ஃபிஷிங் & போலி உள்நுழைவு பக்கங்கள்",
        "desc_en": "Spot psychological urgency tactics, typosquatting, credential harvesting, and OTP theft.",
        "desc_ta": "அவசர தூண்டுதல் தந்திரங்கள், போலி டொமைன்கள், கடவுச்சொல் மற்றும் OTP திருட்டுகளைக் கண்டறியுங்கள்.",
        "guide_id": "qr-phishing"
    },
    {
        "id": "upi-payment",
        "title_en": "UPI & Payment QR Safety",
        "title_ta": "UPI & கட்டண QR பாதுகாப்பு",
        "desc_en": "Understand UPI PIN security, passive fund receiving rules, and merchant standee tampering.",
        "desc_ta": "UPI பின் பாதுகாப்பு, பணம் பெறுவதற்கான விதிகள் மற்றும் போலி QR ஸ்டிக்கர் அபாயங்களைப் புரிந்து கொள்ளுங்கள்.",
        "guide_id": "upi-payment"
    },
    {
        "id": "suspicious-urls",
        "title_en": "Suspicious URL Recognition",
        "title_ta": "சந்தேகத்திற்கிடமான URL அடையாளம் காணுதல்",
        "desc_en": "Identify deceptive subdomains, raw IP addresses, punycode homoglyphs, and link shorteners.",
        "desc_ta": "ஏமாற்று துணை டொமைன்கள், IP முகவரிகள், ஹோமோகிளிஃப் மற்றும் சுருக்கப்பட்ட URL-களைக் கண்டறியுங்கள்.",
        "guide_id": "suspicious-urls"
    },
    {
        "id": "wifi-privacy",
        "title_en": "Wi-Fi QR & Privacy Safety",
        "title_ta": "Wi-Fi QR & தனியுரிமை பாதுகாப்பு",
        "desc_en": "Prevent rogue Evil Twin hotspot traps, credential leakage, and protect sensitive query parameters.",
        "desc_ta": "போலி Evil Twin ஹாட்ஸ்பாட் பொறிகள் மற்றும் கடவுச்சொல் கசிவுகளிலிருந்து தற்காத்துக் கொள்ளுங்கள்.",
        "guide_id": "wifi-safety"
    },
    {
        "id": "redirects-safe-browsing",
        "title_en": "Redirects, Reputation Checks & Safe Browsing",
        "title_ta": "மறுவழிப்படுத்தல், தளம் சரிபார்ப்பு & பாதுகாப்பான உலாவுதல்",
        "desc_en": "Understand multi-hop redirects, SSRF boundaries, external reputation limits, and incident containment.",
        "desc_ta": "பலபடி மறுவழிப்படுத்தல்கள், SSRF தடுப்புகள், தளம் சரிபார்ப்பு வரம்புகள் மற்றும் அவசர மீட்பு முறைகளை அறிதல்.",
        "guide_id": "incident-response"
    }
]

_CACHE: Dict[str, Dict[str, Any]] = {}

def get_performance_tier(percentage: float, lang: str = "en") -> Dict[str, str]:
    """Returns label and styling class based on deterministic percentage thresholds."""
    clamped = max(0.0, min(100.0, percentage))
    for min_p, max_p, label_en, label_ta, badge_class in PERFORMANCE_TIERS:
        if min_p <= clamped <= max_p:
            return {
                "label": label_ta if lang == "ta" else label_en,
                "badge_class": badge_class,
                "tier_key": label_en.lower().replace(" ", "_")
            }
    return {
        "label": "Needs More Practice" if lang == "en" else "கூடுதல் பயிற்சி தேவை",
        "badge_class": "bg-danger",
        "tier_key": "needs_more_practice"
    }

def load_quiz_data(lang: str = "en") -> Dict[str, Any]:
    """Loads and caches question bank for the specified language with fallback to English."""
    norm_lang = "ta" if lang.lower().strip() == "ta" else "en"
    if norm_lang in _CACHE:
        return _CACHE[norm_lang]

    file_path = os.path.join(LOCALES_DIR, f"{norm_lang}.json")
    if not os.path.exists(file_path):
        # Fallback to English if file is not found
        fallback_path = os.path.join(LOCALES_DIR, "en.json")
        with open(fallback_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            _CACHE[norm_lang] = data
            return data

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        _CACHE[norm_lang] = data
        return data

def clear_quiz_cache():
    """Utility for testing or reloading json files."""
    _CACHE.clear()

def get_categories(lang: str = "en") -> List[Dict[str, Any]]:
    """Returns list of all categories with localized titles, descriptions, and question counts."""
    data = load_quiz_data(lang)
    questions = data.get("questions", [])
    
    cat_counts = {}
    for q in questions:
        cid = q.get("category_id")
        cat_counts[cid] = cat_counts.get(cid, 0) + 1

    result = []
    is_ta = (lang.lower().strip() == "ta")
    for meta in CATEGORIES_META:
        cid = meta["id"]
        result.append({
            "id": cid,
            "title": meta["title_ta"] if is_ta else meta["title_en"],
            "description": meta["desc_ta"] if is_ta else meta["desc_en"],
            "question_count": cat_counts.get(cid, 0),
            "languages": ["English", "தமிழ்"],
            "guide_id": meta["guide_id"]
        })
    return result

def get_category_questions_for_client(category_id: str, lang: str = "en") -> List[Dict[str, Any]]:
    """
    Returns questions for a category without the correct_answer field
    to ensure the answer key is never leaked to the client upfront.
    """
    data = load_quiz_data(lang)
    questions = data.get("questions", [])
    filtered = [q for q in questions if q.get("category_id") == category_id]

    client_questions = []
    for q in filtered:
        client_questions.append({
            "id": q["id"],
            "category_id": q["category_id"],
            "difficulty": q.get("difficulty", "beginner"),
            "question": q["question"],
            "options": q["options"],  # List of { "id": "A", "text": "..." }
            "related_guide_id": q.get("related_guide_id", "")
        })
    return client_questions

def check_answer(question_id: str, selected_option_id: str, lang: str = "en") -> Dict[str, Any]:
    """
    Evaluates a single question answer on the server side.
    Returns correctness, correct_answer identifier, explanation, and takeaway.
    """
    data = load_quiz_data(lang)
    questions = data.get("questions", [])
    target_q = next((q for q in questions if q["id"] == question_id), None)

    if not target_q:
        # Check English fallback
        if lang != "en":
            en_data = load_quiz_data("en")
            target_q = next((q for q in en_data.get("questions", []) if q["id"] == question_id), None)

    if not target_q:
        return {
            "success": False,
            "error": "QUESTION_NOT_FOUND",
            "message": f"Question with ID '{question_id}' not found."
        }

    correct_id = target_q["correct_answer"]
    is_correct = (selected_option_id == correct_id)

    # Friendly supportive feedback message
    is_ta = (lang.lower().strip() == "ta")
    if is_correct:
        feedback_msg = "சரியானது! இலக்கை எப்போதும் சரிபார்க்கவும்." if is_ta else "Correct! Remember to verify the destination."
    else:
        feedback_msg = "நல்ல முயற்சி — நீங்கள் கவனிக்க வேண்டியது இங்கே உள்ளது." if is_ta else "Good try — here's what to look for."

    return {
        "success": True,
        "question_id": question_id,
        "selected_option_id": selected_option_id,
        "is_correct": is_correct,
        "correct_answer": correct_id,
        "feedback_message": feedback_msg,
        "explanation": target_q.get("explanation", ""),
        "safety_takeaway": target_q.get("safety_takeaway", ""),
        "related_guide_id": target_q.get("related_guide_id", "")
    }

def evaluate_quiz_submission(category_id: str, answers: List[Dict[str, str]], lang: str = "en") -> Dict[str, Any]:
    """
    Evaluates a full quiz submission where answers is a list of {"question_id": ..., "selected_option_id": ...}.
    Prevents duplicate submissions from counting multiple times.
    """
    data = load_quiz_data(lang)
    questions = {q["id"]: q for q in data.get("questions", []) if q.get("category_id") == category_id}

    if not questions:
        return {
            "success": False,
            "error": "CATEGORY_EMPTY_OR_NOT_FOUND",
            "message": f"No questions found for category '{category_id}'."
        }

    # Dedup submissions by question_id (first submitted answer counts)
    processed_answers: Dict[str, str] = {}
    for item in answers:
        qid = item.get("question_id")
        opt = item.get("selected_option_id")
        if qid in questions and qid not in processed_answers and opt:
            processed_answers[qid] = opt

    total_questions = len(questions)
    correct_count = 0
    incorrect_count = 0
    detailed_results = []
    incorrect_reviews = []
    topics_correct = []
    topics_needing_practice = []

    for qid, q in questions.items():
        user_choice = processed_answers.get(qid)
        is_answered = (user_choice is not None)
        is_correct = False
        correct_id = q["correct_answer"]

        if is_answered:
            if user_choice == correct_id:
                is_correct = True
                correct_count += 1
                if q.get("topic") and q["topic"] not in topics_correct:
                    topics_correct.append(q["topic"])
            else:
                incorrect_count += 1
                if q.get("topic") and q["topic"] not in topics_needing_practice:
                    topics_needing_practice.append(q["topic"])
        else:
            # Unanswered questions earn zero points
            incorrect_count += 1

        res_item = {
            "question_id": qid,
            "question_text": q["question"],
            "options": q["options"],
            "selected_option_id": user_choice,
            "correct_option_id": correct_id,
            "is_correct": is_correct,
            "explanation": q.get("explanation", ""),
            "safety_takeaway": q.get("safety_takeaway", ""),
            "related_guide_id": q.get("related_guide_id", ""),
            "topic": q.get("topic", "")
        }
        detailed_results.append(res_item)

        if not is_correct:
            incorrect_reviews.append(res_item)

    percentage = round((correct_count / total_questions) * 100, 1) if total_questions > 0 else 0.0
    tier_info = get_performance_tier(percentage, lang)

    is_ta = (lang.lower().strip() == "ta")
    if percentage >= 85:
        summary_text = "அருமை! இந்த பிரிவின் பாதுகாப்பு அம்சங்களில் உங்களுக்கு சிறந்த புரிதல் உள்ளது." if is_ta else "Outstanding! You demonstrated an excellent grasp of these cybersecurity concepts."
    elif percentage >= 60:
        summary_text = "நல்ல முன்னேற்றம்! பெரும்பாலான நடைமுறைகளை நீங்கள் சரியாகப் புரிந்துகொண்டுள்ளீர்கள்." if is_ta else "Good progress! You understand the key risks, but review the takeaways below to stay fully secure."
    else:
        summary_text = "கூடுதல் பயிற்சி தேவை. கீழே உள்ள விளக்கங்கள் மற்றும் விழிப்புணர்வு வழிகாட்டிகளைப் படியுங்கள்." if is_ta else "Needs more practice. Review the detailed explanations and safety guides below before retrying."

    return {
        "success": True,
        "category_id": category_id,
        "total_questions": total_questions,
        "correct_count": correct_count,
        "incorrect_count": incorrect_count,
        "unanswered_count": total_questions - len(processed_answers),
        "percentage": percentage,
        "performance_label": tier_info["label"],
        "performance_badge": tier_info["badge_class"],
        "tier_key": tier_info["tier_key"],
        "summary_text": summary_text,
        "topics_correct": topics_correct,
        "topics_needing_practice": topics_needing_practice,
        "incorrect_reviews": incorrect_reviews,
        "detailed_results": detailed_results
    }
