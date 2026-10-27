"""
Modular Threat Detection & Explainable Intelligence Engine for QShield.
Coordinates evidence from:
1. Static structural URL heuristics
2. Advanced lexical feature extraction (20+ features)
3. QR payload classification
4. Optional external threat reputation lookups
5. Optional machine-learning classification models
Produces a standardized, explainable, and confidence-labeled evaluation result.
"""
from typing import Any, Dict, List, Optional
from app.core.feature_extractor import extract_url_features
from app.core.url_analyzer import analyze_url_heuristics
from app.core.risk_scorer import calculate_risk_score, INDICATOR_RECOMMENDATIONS, LIMITATIONS_NOTICE
from app.core.payload_classifier import classify_payload
from app.core.ml_classifier import get_ml_classifier


class ModularDetectionEngine:
    """
    Modular intelligence engine that coordinates multi-source evidence
    with strict separation of local heuristics vs. external feeds.
    """

    def __init__(self, ml_classifier=None):
        self.ml_classifier = ml_classifier or get_ml_classifier()

    def evaluate(
        self,
        raw_input: str,
        scan_type: str = "manual",
        reputation_result: Optional[Dict[str, Any]] = None,
        redirect_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes complete multi-source detection and produces the unified QShield assessment.
        """
        if not isinstance(raw_input, str) or not raw_input.strip():
            return self._build_empty_response()

        cleaned_input = raw_input.strip()

        # 1. Optical Payload Classification
        classification = classify_payload(cleaned_input)
        payload_type = classification.get("payload_type", "unknown")

        evidence_sources = ["payload_classifier"]

        # If payload is NOT a web URL (e.g. Wi-Fi, vCard, Plain Text)
        if payload_type != "url":
            return {
                "analysis_method": "payload_classification_only",
                "risk_score": None,
                "risk_level": "inconclusive",
                "confidence_label": "insufficient_evidence",
                "findings": [],
                "recommendations": [
                    "URL heuristic analysis is not applicable to non-web payloads.",
                    "Review extracted fields safely as text without executing automated actions."
                ],
                "evidence_sources": evidence_sources,
                "limitations": "Non-URL payload. Structural URL risk heuristics do not apply.",
                "analysis_status": "inconclusive",
                "payload_classification": classification,
                "extracted_features": None,
                "ml_assessment": None,
            }

        # 2. Advanced Feature Extraction
        feature_data = extract_url_features(cleaned_input)
        if not feature_data.get("valid"):
            return {
                "analysis_method": "heuristic_rules",
                "risk_score": None,
                "risk_level": "inconclusive",
                "confidence_label": "insufficient_evidence",
                "findings": [],
                "recommendations": ["Submit a valid HTTP or HTTPS web address."],
                "evidence_sources": evidence_sources,
                "limitations": "Input string could not be parsed into a valid web address.",
                "analysis_status": "inconclusive",
                "payload_classification": classification,
                "extracted_features": None,
                "ml_assessment": None,
            }

        extracted_features = feature_data["features"]
        evidence_sources.append("feature_extractor")

        # 3. Static Heuristic Analysis & Base Risk Scoring
        url_analysis = analyze_url_heuristics(cleaned_input)
        risk_data = calculate_risk_score(url_analysis)
        evidence_sources.append("local_heuristics")

        base_score = risk_data.get("score", 0)
        risk_level = risk_data.get("risk_level", "low")

        # 4. Optional Machine-Learning Model Evaluation
        ml_result = self.ml_classifier.predict(cleaned_input)
        if self.ml_classifier.is_available():
            evidence_sources.append("machine_learning_classifier")

        # 5. Enrich Findings with Plain-Language Actionable Advice
        raw_indicators = url_analysis.get("indicators", [])
        enriched_findings: List[Dict[str, Any]] = []

        for ind in raw_indicators:
            ind_id = ind.get("id", "UNKNOWN_INDICATOR")
            suggested_action = INDICATOR_RECOMMENDATIONS.get(
                ind_id,
                "Verify the domain ownership and do not submit credentials without manual confirmation."
            )
            enriched_findings.append({
                "id": ind_id,
                "title": ind.get("title", ind_id),
                "explanation": ind.get("explanation", "Suspicious pattern detected."),
                "severity": ind.get("severity", "info"),
                "evidence": ind.get("evidence", "Pattern match"),
                "suggested_action": suggested_action
            })

        # Additional feature findings (e.g. Open Redirect Parameters or High Entropy)
        if extracted_features.get("has_redirect_param"):
            params_str = ", ".join(extracted_features.get("redirect_params", []))
            enriched_findings.append({
                "id": "URL_REDIRECT_PARAMETER_PRESENT",
                "title": "Embedded Redirection Parameter Detected",
                "explanation": f"The URL query string contains parameter(s) often used for open redirects ({params_str}). Users may be bounced away from the initial host.",
                "severity": "medium",
                "evidence": f"Redirect parameter detected: {params_str}",
                "suggested_action": "Verify where the embedded destination leads before entering credentials."
            })

        if extracted_features.get("query_entropy", 0.0) >= 4.3:
            enriched_findings.append({
                "id": "URL_HIGH_ENTROPY_QUERY",
                "title": "High Lexical Entropy in Query String",
                "explanation": "The URL parameters contain high randomness (Shannon entropy >= 4.3). This is frequently seen in encoded session identifiers or encrypted malware payloads.",
                "severity": "low",
                "evidence": f"Query entropy: {extracted_features['query_entropy']} bits/char",
                "suggested_action": "Avoid interacting with links carrying obscure, randomized query strings."
            })

        # 6. Optional Threat Intelligence Feed Integration
        analysis_method = "heuristic_rules"
        if reputation_result and reputation_result.get("status") == "checked":
            evidence_sources.append("threat_intelligence_feed")
            analysis_method = "heuristic_plus_threat_feed"
            if reputation_result.get("reputation") == "malicious":
                risk_level = "critical"
                base_score = max(base_score, 85)

        if self.ml_classifier.is_available():
            analysis_method = "hybrid_ensemble"

        # 7. Confidence & Sufficiency Determination
        # High confidence if complete URL with registered domain analyzed
        if len(enriched_findings) > 0 and base_score >= 50:
            confidence_label = "high"
        elif base_score is not None:
            confidence_label = "medium"
        else:
            confidence_label = "insufficient_evidence"

        # Recommendations
        recommendations = list(risk_data.get("recommendations", []))
        if not recommendations:
            recommendations = [
                "Verify the domain directly by typing the official address into your browser.",
                "Never submit passwords, OTPs, or financial details across unverified web pages."
            ]

        return {
            "analysis_method": analysis_method,
            "risk_score": base_score,
            "risk_level": risk_level,
            "confidence_label": confidence_label,
            "findings": enriched_findings,
            "recommendations": recommendations,
            "evidence_sources": evidence_sources,
            "limitations": LIMITATIONS_NOTICE,
            "analysis_status": "completed",
            "payload_classification": classification,
            "extracted_features": extracted_features,
            "ml_assessment": ml_result,
            "reputation_assessment": reputation_result,
            "redirect_assessment": redirect_result,
        }

    def _build_empty_response(self) -> Dict[str, Any]:
        return {
            "analysis_method": "none",
            "risk_score": None,
            "risk_level": "inconclusive",
            "confidence_label": "insufficient_evidence",
            "findings": [],
            "recommendations": ["Submit a valid QR code or URL to inspect."],
            "evidence_sources": [],
            "limitations": LIMITATIONS_NOTICE,
            "analysis_status": "failed",
            "payload_classification": None,
            "extracted_features": None,
            "ml_assessment": None,
        }


# Global shared instance
_detection_engine = ModularDetectionEngine()


def get_detection_engine() -> ModularDetectionEngine:
    """Returns the shared ModularDetectionEngine instance."""
    return _detection_engine
