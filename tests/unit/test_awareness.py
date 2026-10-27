"""
Unit tests for QShield Bilingual Awareness Centre data and locale files.
Verifies JSON validity, schema parity between English and Tamil,
guide identifiers, scenario options, and checklist completeness.
"""
import os
import json
import pytest

LOCALES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "locales")

def load_locale(lang):
    file_path = os.path.join(LOCALES_DIR, f"{lang}.json")
    assert os.path.exists(file_path), f"Locale file {file_path} missing"
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def test_locales_exist_and_load_valid_json():
    en_data = load_locale("en")
    ta_data = load_locale("ta")
    assert isinstance(en_data, dict)
    assert isinstance(ta_data, dict)

def test_locale_key_parity():
    en_data = load_locale("en")
    ta_data = load_locale("ta")

    # Top-level keys must match
    assert set(en_data.keys()) == set(ta_data.keys())

    # Guide keys must match
    assert set(en_data["guides"].keys()) == set(ta_data["guides"].keys())
    assert len(en_data["guides"]) == 8

    for guide_key in en_data["guides"]:
        en_guide = en_data["guides"][guide_key]
        ta_guide = ta_data["guides"][guide_key]
        assert en_guide["id"] == ta_guide["id"]
        assert len(en_guide["points"]) == len(ta_guide["points"])
        assert len(en_guide["points"]) >= 4

    # Scenarios parity
    assert len(en_data["scenarios"]) == 6
    assert len(ta_data["scenarios"]) == 6
    for i in range(6):
        en_scen = en_data["scenarios"][i]
        ta_scen = ta_data["scenarios"][i]
        assert en_scen["id"] == ta_scen["id"]
        assert en_scen["correct_index"] == ta_scen["correct_index"]
        assert len(en_scen["options"]) == len(ta_scen["options"])

    # Checklist items parity
    assert len(en_data["checklist_items"]) == 7
    assert len(ta_data["checklist_items"]) == 7

def test_tamil_unicode_characters_present():
    ta_data = load_locale("ta")
    # Verify non-empty Tamil text in hero, guides, scenarios, checklist
    assert "சிந்தியுங்கள்" in ta_data["hero_heading"]
    assert any("ரூ." in scen["situation"] or "ரூ." in scen["question"] or "பணம்" in scen["explanation"] for scen in ta_data["scenarios"])
    for item in ta_data["checklist_items"]:
        assert len(item) > 10
        # Check Tamil unicode range \u0b80-\u0bff
        assert any('\u0b80' <= c <= '\u0bff' for c in item)
