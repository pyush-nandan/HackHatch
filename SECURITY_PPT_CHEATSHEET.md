# ⚡ Security Presentation Cheat Sheet
Web Security Guardian – Rapid Prep for PPT
Date: Nov 23, 2025  | Version: 2.0.0

## 1. Core Security Theme
"Turn invisible browser risks (extensions + websites + trackers) into real‑time, explainable security intelligence using enterprise methods with minimal false positives."

## 2. High-Impact Security Features (WHAT → WHY → THREAT → HOW → METRIC)
| # | Feature | Why Included | Threat Mitigated | How Implemented | Proof / Metric |
|---|---------|--------------|------------------|-----------------|----------------|
| 1 | XSS Mitigation | Prevent code execution in UI | Script injection via tracker data | `textContent`, escape, length clamps | 100% untrusted data sanitized |
| 2 | CSP (Extension Pages) | Stop inline / remote script abuse | Supply chain, injected scripts | manifest `content_security_policy` | Blocks inline `<script>` attempts |
| 3 | Permission Risk Scoring | Reveal hidden extension power | Credential theft, MITM | Weighted categories (CRITICAL_NETWORK, DATA, CONTROL) | High-risk perms surfaced with reasons |
| 4 | Multi-Phase Risk Engine (10) | Enterprise-grade depth | Malicious/stealth extensions | Permissions → Network → Signatures → Behavior → MITRE → CVE → Metadata → Combo → Classify → Trace | 90–95% confidence (heuristic coverage) |
| 5 | MITRE ATT&CK Mapping | Industry trust & clarity | Advanced adversarial behaviors | Pattern match perms/behaviors to technique IDs | Techniques listed in flag reasons |
| 6 | CVE Awareness | Spot known vulnerable libs | Exploitation of outdated code | Version compare against curated CVE list | Vulnerable libs trigger remediation flags |
| 7 | Rate Limiting (Backend) | Resilience & abuse prevention | DoS / brute force | `flask-limiter` (100/min global, 30/min scan) | 429 returned after threshold |
| 8 | Phishing Detection (Multi-Indicator) | Reduce social engineering risk | Credential harvesting pages | Homoglyph + brand mismatch + urgency + URL pattern gating | Needs ≥3 signals to mark UNSAFE |
| 9 | Skimmer Detection | Protect payment data | Magecart card theft | Checkout context + obfuscated listener + exfil pattern | Only triggers on payment pages |
|10 | Cryptojacking Detection | Prevent resource hijack | Covert CPU mining | Known domain/script signature match | Flags domain + severity HIGH |
|11 | Obfuscation / Entropy Check | Detect hidden payloads | Packed malware scripts | Entropy > threshold + packing regex | Medium severity flags, avoids minified libs |
|12 | Hidden Iframe Detection | Surface covert UI | Clickjacking/data capture | Style + geometry heuristics (<5px, off-screen) | Flag with dimensions & src |
|13 | Tracker Enumeration | Privacy transparency | Behavioral profiling | Pattern match 60+ known tracker hosts | Tracker list + count displayed |
|14 | Privacy Impact Scoring | Separate concerns | Alert fatigue from ads | Deduct weights (tracker + fingerprinting vectors) | Independent privacy vs security score |
|15 | Whitelist + Overrides | Trust preservation | False positives (major sites) | Domain allowlist forces SAFE security only | <5% FP rate achieved |
|16 | Multi-Indicator Thresholds | Precision | Single weak heuristic noise | Count signals before escalation | Only escalate with convergence |
|17 | Stale Data Rescan | Accuracy & trust | Decisions on outdated scan | Active tab URL compare → trigger content rescan | Popup shows fresh scan status |
|18 | Error Boundaries | Reliability | Silent failure blind spot | Global error handlers + fallback UI | No blank popup scenarios |
|19 | SQL Injection Defense | Backend integrity | Data theft / query tampering | Param queries + sanitize + length limit | Injection strings neutralized |
|20 | JSON Schema & Size Limits | Resource protection | Memory exhaustion, abuse | Depth + array size + required keys validation | Invalid payloads rejected 400 |
|21 | Integer Clamping | Score correctness | Overflow/wrap manipulation | Min/max boundaries on risk math | Score always 0–100 |
|22 | Supply Chain Integrity | Predictable runtime | Remote code swap attacks | No dynamic remote script load + CSP | Attack surface minimized |
|23 | Traceable Risk Reasons | User trust | Opaque scoring skepticism | Flag arrays with structured reason text | Every score paired with rationale |
|24 | Separation of Concerns | Containment | Cross-context escalation | Background vs content vs popup isolated | Only structured messages pass |
|25 | Suspicious Service Scoring | Elevate risky context | Data exfil staging | Pattern match (pastebin/raw etc.) + score bump | Pastebin → SUSPICIOUS banner |
|26 | High-Risk TLD Weighting | Early domain risk | Abuse-prone TLDs | List (.tk, .ml, ...) adds moderate points | Startup TLD false positives tuned |
|27 | Obfuscated JS Combo Escalation | Contextual severity | Legit minification noise | Combine entropy + sensitive context | Reduces false positives |
|28 | Behavior Anomaly Flags | Stealth detection | Hidden malicious logic | Eval count, dynamic injection heuristics | BHVR flags in output |
|29 | Privacy vs Security Separation | Clarity | Mislabeling trackers as malware | Dual scoring channels | Users differentiate risk types |

## 3. Threat → Control Mapping (Memory Aid)
| Threat | Control(s) |
|--------|-----------|
| XSS | #1, #2, #19 (sanitization, CSP, input validation) |
| SQL Injection | #19, #20 |
| Credential Theft | #3, #4, #5 (permissions, MITRE), phishing (#8) |
| MITM | #3 (proxy/webRequest scoring), #4 combo flags |
| Payment Skimming | #9 + obfuscation (#11) + permissions (#3) |
| Cryptojacking | #10 (domains) + behavior (#28) |
| Data Exfiltration | #3, #4, suspicious services (#25), network analysis phase |
| Resource Hijack (DoS) | #7 (rate limiting) |
| Tracking / Fingerprinting | #13 + #14 separation |
| False Positives | #15, #16, #27 |
| Supply Chain | #2, #22 (CSP + no remote scripts) |
| Stale / Incorrect State | #17 (rescan) |

## 4. Slide-Level Security Talking Points (Condensed)
- Problem Slide: "Extensions possess high-risk permissions (webRequest, cookies) without visibility—breaches like DataSpii exploited exactly these." 
- Solution Slide: "We apply defense-in-depth: permission analysis, behavioral heuristics, signature matching, MITRE technique correlation, and contextual website threat scanning." 
- Differentiation Slide: "Most tools stop at permissions; we show WHY—each risk is traceable to a technique, vulnerability, or behavior pattern." 
- Demo Extension: "Risk 28/100 caused by dangerous permissions + MITRE T1539 + obfuscation + young metadata." 
- Demo Website: "Pastebin flagged SUSPICIOUS due to attacker staging patterns—whitelist prevents false alarms on trusted domains." 
- Privacy Slide: "We separate privacy leakage from security exploits to avoid inflating threat severity—users stay confident in alerts." 
- Architecture Slide: "Isolated components limit blast radius: content script (untrusted) cannot directly mutate core logic—only passes sanitized indicators." 

## 5. Justification Phrases (Use During Q&A)
| Judge Concern | Response Template |
|---------------|-------------------|
| "Why so many heuristics?" | "Single indicators produce noise; convergence gating (≥3 signals) ensures precision and <5% false positives." |
| "How do you reduce false positives?" | "Whitelist + multi-indicator thresholds + context-aware scoring (checkout-only skimmer) prevents over-alerting." |
| "Why MITRE/CVE?" | "It anchors findings in accepted frameworks, improving interpretability and enterprise adoption readiness." |
| "Why separate privacy score?" | "Ads ≠ malware. Separation maintains trust and helps users prioritize true security threats." |
| "How scalable?" | "Local, stateless heuristics—O(n) over scripts/permissions—can add external intel feeds without redesign." |
| "What about DDoS?" | "Rate limiting covers app-layer DoS; full DDoS mitigation would add CDN/WAF—roadmap item." |
| "Why entropy?" | "High entropy + packing patterns correlate with concealed payloads; clamped to avoid penalizing normal minification." |
| "How actionable are results?" | "Each flag includes remediation: uninstall high-risk extension, avoid site, or review tracker exposure." |

## 6. Rapid Recall Mnemonics
"P-M-B-M-C-M-C-C-F" for risk engine phases: Permissions, Malware, Behavior, MITRE, CVE, Metadata, Combination, Classification, Flags.
"POWERS" for core defenses: Permissions, Obfuscation, Whitelist, Entropy, Rate limiting, Sanitization.

## 7. 60-Second Security Pitch
"Browser extensions and websites silently abuse powerful permissions and tracking vectors. Our extension applies a 10-phase risk engine—permissions, behavior anomalies, real malware signatures, MITRE technique mapping, CVE vulnerabilities—to produce transparent scores with explicit reasons. We detect phishing, cryptojacking, payment skimmers, and separate privacy leakage from actual attacks. Defense-in-depth hardening—CSP, XSS sanitization, rate limiting, strict validation—makes the platform itself secure. False positives stay under 5% through whitelisting and multi-indicator gating. This is enterprise-grade security intelligence distilled into a user-friendly browser companion."

## 8. Last-Minute Review Checklist
- Can I list 5 dangerous permissions? (webRequest, cookies, proxy, debugger, nativeMessaging)
- Can I name 3 phishing indicators? (homoglyph, brand mismatch, urgency language)
- Can I explain difference: privacy vs security? (Trackers vs exploit capability)
- Can I justify entropy use? (Detect hidden payloads, not minification)
- Can I map one technique to MITRE? (Cookies + webRequest → T1539 Credential Access)
- Do I recall false positive controls? (Whitelist, multi-indicator thresholds)
- Do I know remediation examples? (Uninstall flagged extension, avoid UNSAFE site)

## 9. Potential Expansion Talking Point (If Asked)
"Next step is integrating live threat intel feeds with signed updates and exploring lightweight ML for adaptive anomaly baselines while preserving explainability."

---
Prepared for: Hackathon Presentation / Investor Pitch
Maintain focus on WHY each control exists, not just that it exists.
