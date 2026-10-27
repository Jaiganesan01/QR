# QShield Risk Analytics Methodology & Calculation Logic

## 1. Risk Category Definitions

QShield evaluates risk scores on a standardized scale from 0 to 100 based on weighted lexical and structural indicators:

| Tier | Score Range | Classification | Actionable Guidance |
| :--- | :--- | :--- | :--- |
| **Low Risk** | 0 – 19 | Minimal Threat | Destination shows no anomalous structural patterns. |
| **Medium Risk** | 20 – 49 | Suspicious Elements | Contains minor anomalies (e.g. shortener, non-standard port). |
| **High Risk** | 50 – 79 | Elevated Threat | Significant deception patterns (e.g. brand in subdomain, IP host). |
| **Critical Risk** | 80 – 100 | Severe Threat | Explicit phishing hallmarks, embedded userinfo, or feed flags. |
| **Inconclusive** | None | Non-URL / Format Notice | Plain text, vCard, or Wi-Fi configurations where URL rules do not apply. |

---

## 2. Indicator Counting Rules

To ensure reporting accuracy:
- **Unique Scans per Indicator:** When reporting indicator frequency, QShield counts the number of distinct scans exhibiting the indicator (`COUNT(DISTINCT scan_id)`). If a rule fires multiple times within a single URL, it is counted once for that scan's indicator tally to avoid distortion.
- **Structural vs External Separation:** Structural anomalies (such as raw IP hosts or brand mimicry) are explicitly categorized as `structural` evidence. External reputation checks (Google Safe Browsing or VirusTotal) are labeled as `external_confirmed` detections.
- **Educational Guidance:** The dashboard and API explicitly communicate that a structural indicator is observable evidence for human review, not definitive proof of malicious intent.

---

## 3. Detection Method Definitions

Metrics for detection methods reflect **actual runtime execution**:
- **Deterministic Heuristic Rules (`heuristic_rules`):** Offline static analysis of URL structure, tokens, entropy, and length metrics.
- **Machine Learning Inference (`ml_inference`):** Scored using a validated local scikit-learn model artifact.
- **Modular Intelligence Ensemble (`ensemble`):** Unified multi-source assessment combining heuristics, feature vectors, and ML classifications.
- **Inconclusive / Other (`inconclusive`):** Non-URL payloads or unparseable optical codes.

*Note: Unconfigured threat intelligence feeds or missing API keys are not counted as successful lookups.*

---

## 4. Period Trend Comparison Logic

QShield compares the active time window against an immediately preceding period of equal length:
- **24 Hours:** Last 24 hours ($T_0$ to $T_{-24h}$) vs Preceding 24 hours ($T_{-24h}$ to $T_{-48h}$).
- **7 Days:** Last 7 days ($T_0$ to $T_{-7d}$) vs Preceding 7 days ($T_{-7d}$ to $T_{-14d}$).
- **30 Days:** Last 30 days ($T_0$ to $T_{-30d}$) vs Preceding 30 days ($T_{-30d}$ to $T_{-60d}$).

### Guardrails:
1. **Division-by-Zero Protection:** If the previous period volume is 0 and current volume is $>0$, percentage change is set to `null` and displayed as `+N (new activity)` to prevent `ZeroDivisionError`.
2. **Small Dataset Threshold:** If total records across both comparison periods are fewer than 5, trend calculation flags `has_sufficient_data: false` and displays: *"Not enough data to identify a trend."*
3. **Local Scope Disclaimer:** All trend summaries include the explicit disclaimer: *"Local scan activity only; does not represent global cyber threat patterns."*

---

## 5. Known Data-Quality Limitations

1. **Local Deployment Bias:** Trends reflect only user submissions made to this specific instance.
2. **Offline Boundaries:** Without dynamic browser sandboxing, pages with benign URLs that load client-side JavaScript exploits cannot be detected purely from URL syntax.
3. **User Opt-in for Threat Feeds:** External reputation checks are performed only with explicit user consent to safeguard privacy.
