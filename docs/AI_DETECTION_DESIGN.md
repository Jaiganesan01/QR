# QShield AI-Powered Threat Detection & Intelligence Engine Design

**Project:** QShield — QR Phishing Detection & Awareness System  
**Tagline:** “Decode the QR. Detect the Threat.”  
**Milestone:** Prompt 18 — AI-Powered QR Threat Detection & Explainable Intelligence Engine

---

## 1. Executive Summary & Design Rationale

QShield currently protects users through deterministic optical decoding, payload classification, and a 12-rule static heuristic URL analyzer. While heuristic rules are effective at intercepting overt evasion techniques (such as embedded credentials, brand tokens in subdomains, raw IP destinations, and Punycode homoglyphs), modern phishing actors frequently evolve subtle syntactic permutations (e.g. multi-hop redirect parameters, high-entropy query tokens, excessive percent-encoding, and complex hyphenated domain structures).

The objective of this upgrade is to introduce an **Explainable Intelligence Engine** that:
1. **Expands Local Feature Extraction:** Analyzes 20+ granular structural and lexical URL features (entropy, character ratios, redirect parameters, encoding depth) with zero outbound network calls.
2. **Standardizes the Internal Detection Schema:** Defines a unified result format across heuristic analysis, external reputation feeds, and optional machine-learning models.
3. **Implements an Optional ML Interface with Safe Fallback:** Provides a robust ML model adapter interface that cleanly distinguishes available vs. unconfigured states without fabricating predictions or breaking local heuristic reliability.
4. **Enforces Evidence-Distinguished Ensemble Logic:** Combines local structural signals, optional third-party reputation hits, and model confidence without conflating unconfirmed heuristics with authoritative reputation detections.

---

## 2. Current Architecture vs. Proposed Intelligence Architecture

### Current Detection Baseline (Prompts 1–17)
- **Decoding:** OpenCV `cv2.QRCodeDetector` extracts text in-memory.
- **Classification:** 12 regex-based payload formats (URL, Wi-Fi, vCard, etc.).
- **URL Analysis:** 12 fixed rules in `app/core/url_analyzer.py` mapping directly to base weights in `app/core/risk_scorer.py`.
- **Threat Intel:** Optional Google Safe Browsing client requiring explicit user consent.
- **Limitation:** Feature extraction and scoring are tightly coupled; no standardized feature vector exists for ML experimentation; evidence sources are reported in separate dictionary keys.

### Proposed Detection Engine (Prompt 18)

```mermaid
flowchart TD
    RawInput["Decoded QR Payload or Manual URL"] --> PayloadClassifier["Payload Classifier (Format Identification)"]
    PayloadClassifier -->|Non-URL (Wi-Fi, vCard, Text)| SafeRenderer["Safe Text Inspection (Mask Credentials, Inconclusive Risk)"]
    PayloadClassifier -->|Valid Web URL| FeatureExtractor["Advanced URL Feature Extractor (20+ Lexical/Structural Features)"]
    
    subgraph ModularEngine["Modular Detection Engine (app.core.detection_engine)"]
        FeatureExtractor --> RuleEvaluator["Heuristic Rule Evaluator (Explainable Indicators & Family Discounting)"]
        FeatureExtractor --> MLAdapter["ML Classifier Adapter (Optional Inference / Fallback if Model Unconfigured)"]
        ThirdPartyFeed["External Threat Intel (Optional, Consent-Gated Safe Browsing)"] -.-> EnsembleDecision["Ensemble Decision & Confidence Layer"]
        
        RuleEvaluator --> EnsembleDecision
        MLAdapter --> EnsembleDecision
    end

    EnsembleDecision --> UnifiedOutput["Unified Detection Result"]
    UnifiedOutput --> ScanResultsUI["Progressive Disclosure Scan UI (English & Tamil)"]
    UnifiedOutput --> HistoryDB["Sanitized Metadata Store (Privacy-by-Design)"]
    UnifiedOutput --> PDFReport["In-Memory PDF Security Report"]
```

---

## 3. Advanced Feature Extraction Specification

The feature extraction layer (`app/core/feature_extractor.py`) processes input URLs through purely local string and syntactic algorithms. **Zero DNS requests, socket connections, or external API queries are performed.**

| Feature Group | Specific Attributes Extracted | Defensive Rationale |
| :--- | :--- | :--- |
| **Length & Dimensionality** | `url_length`, `hostname_length`, `path_length`, `query_length` | Long URLs and elongated paths are frequently used to push the actual domain off-screen on mobile devices. |
| **Structural Complexity** | `subdomain_count`, `subdomain_depth`, `consecutive_dots`, `hyphen_count_hostname` | Multiple subdomain levels and heavily hyphenated domains are common in phishing kit auto-generation. |
| **Obfuscation & Encoding** | `percent_encoding_count`, `is_punycode`, `excessive_encoding` | Double-encoding or percent-encoding (`%20`, `%2e`) masks directory traversal and evasion patterns. |
| **Redirection & Evasion** | `redirect_param_count`, `has_redirect_param`, `is_shortener` | Query keys like `redirect=`, `url=`, `next=`, `dest=`, `dest_url=` indicate open redirects. |
| **Lexical & Entropy** | `path_entropy`, `query_entropy`, `digit_ratio_hostname`, `special_char_count` | High Shannon entropy ($H \ge 4.2$) strongly correlates with randomized token generation or encrypted query blobs. |
| **Deception & Authority** | `has_userinfo`, `is_ip_host`, `is_standard_port`, `brand_mimicry_detected` | Deceptive userinfo (`@`) and brand tokens in subdomains mimic authoritative corporate portals. |
| **Keyword Context** | `credential_keyword_count`, `urgency_keyword_count` | Login, security challenge, and suspension keywords paired with unfamiliar domains. |

---

## 4. Unified Result Schema

The intelligence engine returns a standardized dictionary:

```python
{
    "analysis_method": "heuristic_rules",       # "heuristic_rules", "hybrid_ensemble", "heuristic_plus_threat_feed"
    "risk_score": 55,                           # Integer 0-100 or None if Inconclusive
    "risk_level": "high",                       # "low", "medium", "high", "critical", "inconclusive"
    "confidence_label": "high",                 # "high", "medium", "low", "insufficient_evidence"
    "findings": [
        {
            "id": "URL_BRAND_IN_SUBDOMAIN",
            "title": "Brand Token in Subdomain",
            "explanation": "The brand name 'paypal' appears in the subdomain prefix...",
            "severity": "high",
            "evidence": "paypal found in subdomain of verify-portal.xyz",
            "suggested_action": "Do not enter credentials; verify official domain."
        }
    ],
    "recommendations": [
        "Verify domain directly by typing the official address into your browser."
    ],
    "evidence_sources": ["local_heuristics", "payload_classifier"],
    "limitations": "Deterministic heuristic evaluation. Does not guarantee safety.",
    "analysis_status": "completed"              # "completed", "inconclusive", "failed"
}
```

---

## 5. Decision Layer & Ensemble Logic

1. **Separation of Evidence Sources:**
   - **Local Heuristics:** Evaluates lexical and structural features.
   - **External Reputation:** Evaluates whether a domain is an indexed, reported malicious destination.
   - **Model Prediction:** Evaluates non-linear statistical feature weights if an ML model is loaded.
2. **No Double-Counting:** Correlated indicators within the same family receive discounted weights (50% reduction for secondary findings).
3. **No False Equivalence:** A negative or clean result from an external reputation provider or ML model **never** overrides high-risk structural findings (e.g. userinfo `@` deception or brand impersonation).
4. **Graceful Fallbacks:** If an optional model or threat feed is absent, the engine accurately labels `analysis_method: "heuristic_rules"` rather than claiming an AI ensemble executed.

---

## 6. Implementation Boundaries & Limitations

1. **Dataset Availability:** No validated offline phishing training dataset is bundled in the core repository. Therefore, the ML adapter will safely report `status: "unavailable"` and fall back cleanly to local heuristics.
2. **Client-Side Progressive Disclosure:** Advanced signals are presented progressively in the user interface to ensure clarity for beginners while exposing deep technical telemetry for security practitioners.
3. **Zero Outbound Calls:** Ordinary analysis remains strictly offline. Threat intelligence and redirect inspection remain opt-in with explicit user consent.
