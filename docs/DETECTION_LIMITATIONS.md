# QShield Threat Detection Scope & Operational Limitations

**Project:** QShield — QR Phishing Detection & Awareness System  
**Tagline:** “Decode the QR. Detect the Threat.”

---

## 1. Heuristic Risk vs. Statistical Probability

> [!CAUTION]
> **Defensive Engineering Disclaimer:**  
> The QShield risk score (0–100) is a deterministic heuristic indicator derived from static structural patterns. It is **NOT** a calibrated mathematical probability that a website is malicious, nor does it guarantee that an unflagged URL is safe.

1. **Evasion Indicators, Not Guilt:** A heuristic flag (such as an unencrypted HTTP link or an unusually long URL) highlights a potential evasion pattern or configuration risk. Legitimate internal portals or academic pages may also exhibit these traits.
2. **Absence of Detection $\ne$ Safety:** If a URL triggers 0 heuristic rules and has 0 Google Safe Browsing hits, this simply indicates that no configured structural violations or cataloged threats were identified. An attacker who registers a brand-new domain with standard HTTPS formatting and clean syntax will pass static heuristics undetected until the domain is reported and indexed.

---

## 2. Machine-Learning & Statistical Limitations

1. **Training Set Drift:** Phishing tactics evolve rapidly. Models trained on historical corpora suffer from distribution shift as threat actors adopt new cloud infrastructure, serverless redirectors, and novel top-level domains.
2. **Feature Collisions:** Legitimate enterprise tracking URLs (e.g. email newsletters, marketing analytics links) frequently carry high entropy, numerous query parameters, and redirect targets, creating unavoidable false-positive risks for statistical models.
3. **Pluggable Architecture:** In this release, ML inference is configured as an optional adapter. When unconfigured, the system explicitly reports `status: "unavailable"` and falls back to deterministic rules. Predictions are never fabricated.

---

## 3. Threat Intelligence Latency

1. **Zero-Day Blind Spot:** Reputation providers (such as Google Safe Browsing) require automated crawlers or community telemetry to identify, analyze, and blacklist malicious sites. Newly spun-up quishing URLs may remain uncataloged for hours or days during active campaigns.
2. **Privacy Filtering Constraints:** In adherence to Privacy-by-Design, QShield automatically aborts external reputation queries if the URL contains tokens, passwords, or session IDs. While this shields user credentials from third-party leakage, it means confidential URLs cannot be validated against external feeds.

---

## 4. Optical QR Capture & Computer Vision Boundaries

1. **Physical Degradation:** Extremely low-resolution camera sensors, severe glare, lens smudge, physical tearing, or extreme perspective angles ($\ge 45^\circ$) may prevent OpenCV from isolating the QR finder patterns, returning `NO_QR_DETECTED`.
2. **Dynamic / Animated QR Codes:** QShield inspects static 2D image matrices; it does not process video feeds or rotating multi-frame QR sequences.

---

## 5. Network & Dynamic Content Execution Boundaries

1. **Zero-Outbound Default:** For security and privacy, QShield never visits or executes destination URLs during standard scanning. It does not run client-side JavaScript, inspect DOM trees, or capture browser rendering screenshots.
2. **Meta-Refresh & JavaScript Redirects:** The Safe Redirect Inspector traces HTTP 3xx headers (`Location: ...`). Redirection logic implemented via client-side JavaScript (`window.location = ...`) or HTML `<meta http-equiv="refresh">` tags cannot be evaluated without a dynamic headless browser sandbox.
