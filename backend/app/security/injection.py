from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from ..contracts import Evidence, ThreatLevel, Verdict


@dataclass(frozen=True)
class DetectionResult:
    verdict: Verdict
    threat_level: ThreatLevel
    evidence: list[Evidence]


# ──────────────────────────────────────────────────────────────────
# Pattern Library  (pattern, evidence_code, confidence)
# Grouped by attack class for easier auditing
# ──────────────────────────────────────────────────────────────────

PATTERNS: list[tuple[str, str, float]] = [

    # ── Instruction override ─────────────────────────────────────
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",  "INSTRUCTION_OVERRIDE",   0.97),
    (r"disregard\s+(all\s+)?(previous|prior|above)?\s*(instructions?|rules?|constraints?)", "INSTRUCTION_OVERRIDE", 0.96),
    (r"override\s+(the\s+)?(system\s+)?(prompt|instructions?)", "INSTRUCTION_OVERRIDE", 0.96),
    (r"forget\s+(everything|all|what)\s+(you'?ve?\s+)?(been\s+)?(told|trained|instructed)", "INSTRUCTION_OVERRIDE", 0.95),

    # ── System prompt exfiltration ────────────────────────────────
    (r"(print|output|show|repeat|reveal|tell me|give me)\s+(your\s+)?(system|full|initial|hidden|original)\s+prompt", "PROMPT_EXFILTRATION", 0.97),
    (r"reveal\s+(your\s+)?(instructions|training|system\s+prompt|configuration)", "SECRET_EXFILTRATION", 0.95),
    (r"what\s+(are|were)\s+your\s+(original|initial|hidden|secret)\s+instructions?", "SECRET_EXFILTRATION", 0.90),
    (r"display\s+the\s+(contents\s+of\s+)?system\s+prompt", "PROMPT_EXFILTRATION", 0.95),
    (r"return\s+everything\s+above\s+this\s+line", "PROMPT_EXFILTRATION", 0.93),

    # ── System token injection ────────────────────────────────────
    (r"\[SYSTEM\]|\[INST\]|<\|system\|>|<\|im_start\|>|<<SYS>>|<s>|</s>", "SYSTEM_TOKEN_INJECTION", 0.92),
    (r"###\s*System\s*:|###\s*Human\s*:|###\s*Assistant\s*:", "SYSTEM_TOKEN_INJECTION", 0.88),
    (r"<system>|<user>|<assistant>",  "SYSTEM_TOKEN_INJECTION", 0.85),

    # ── Jailbreaks ───────────────────────────────────────────────
    (r"\bDAN\b\s*(mode|activated|prompt)?", "JAILBREAK_DAN", 0.96),
    (r"jailbreak|jail\s*break", "JAILBREAK", 0.95),
    (r"developer\s+mode\s+(enabled|activated|on|unlocked)?", "JAILBREAK_DEVMODE", 0.94),
    (r"(enable|activate|enter)\s+developer\s+mode", "JAILBREAK_DEVMODE", 0.93),
    (r"god\s*mode|unrestricted\s+mode|freedom\s+mode", "JAILBREAK", 0.91),
    (r"pretend\s+(there\s+are\s+no\s+rules|you\s+have\s+no\s+restrictions?)", "JAILBREAK", 0.90),

    # ── Role hijack ──────────────────────────────────────────────
    (r"you\s+are\s+now\s+(a|an|the)?\s*\w+\s*(ai|model|bot|assistant)?", "ROLE_HIJACK", 0.85),
    (r"from\s+now\s+on\s+(you\s+)?(are|will\s+be|must\s+act\s+as)", "ROLE_HIJACK", 0.84),
    (r"your\s+(new\s+)?(name|role|identity|persona)\s+is", "ROLE_HIJACK", 0.83),
    (r"act\s+as\s+(if|though|a|an)\s+", "ROLE_PLAY_BYPASS", 0.75),
    (r"simulate\s+(being|an?)\s+\w+\s*(without|that\s+ignores)\s+(rules|restrictions?|constraints?)", "ROLE_PLAY_BYPASS", 0.88),

    # ── Data exfiltration ────────────────────────────────────────
    (r"(send|email|exfiltrate|upload|post|transmit)\s+(all|the|my|user)\s*(data|files?|credentials?|keys?|secrets?)", "DATA_EXFILTRATION", 0.95),
    (r"extract\s+and\s+(send|return|output)\s+(all|the)\s+(data|contents?|files?)", "DATA_EXFILTRATION", 0.93),
    (r"(access|read)\s+\/(etc\/passwd|etc\/shadow|\.env|\.ssh\/id_rsa)", "FILE_TRAVERSAL", 0.99),
    (r"\.\.[\/\\]\.\.[\/\\]", "PATH_TRAVERSAL", 0.97),

    # ── SQL injection ────────────────────────────────────────────
    (r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+", "SQL_INJECTION", 0.90),
    (r"union\s+(all\s+)?select", "SQL_INJECTION", 0.97),
    (r"(drop|delete|truncate)\s+(table|database|from)\s+", "SQL_INJECTION", 0.96),
    (r"(insert|update)\s+into\s+\w+\s+(values|set)\s*\(", "SQL_INJECTION", 0.85),
    (r"';\s*(select|drop|insert|update|delete)", "SQL_INJECTION", 0.95),
    (r"--\s*(select|drop|insert|update|delete|admin|pass)", "SQL_INJECTION", 0.88),

    # ── SSRF / open redirect ─────────────────────────────────────
    (r"(fetch|get|request|curl|wget|http\.get)\s*(from\s+)?https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "SSRF", 0.92),
    (r"(fetch|access|curl|wget)\s+https?://(localhost|127\.0\.0\.1|169\.254|192\.168|10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.)", "SSRF", 0.98),
    (r"file://|dict://|gopher://|ftp://internal|ftp://192\.", "SSRF", 0.95),

    # ── Privilege escalation ─────────────────────────────────────
    (r"(run|execute|call)\s+as\s+(root|sudo|admin|superuser)", "PRIVILEGE_ESCALATION", 0.94),
    (r"sudo\s+(su|bash|sh|root|chmod\s+777|rm\s+-rf)", "PRIVILEGE_ESCALATION", 0.96),
    (r"chmod\s+[0-7]*7[0-7]*[0-7]*\s", "PRIVILEGE_ESCALATION", 0.88),

    # ── Shell injection ──────────────────────────────────────────
    (r";\s*(rm|cat|wget|curl|bash|sh|python|perl|nc)\s", "SHELL_INJECTION", 0.94),
    (r"\|\s*(bash|sh|python|perl|nc|ncat)\s", "SHELL_INJECTION", 0.93),
    (r"`[^`]{3,}(rm|bash|sh|wget|curl)[^`]*`", "SHELL_INJECTION", 0.91),
    (r"\$\([^)]{3,}(rm|bash|sh|wget|curl)[^)]*\)", "SHELL_INJECTION", 0.90),
]

# ──────────────────────────────────────────────────────────────────
# Entropy scoring: high randomness + short tokens = suspicious
# ──────────────────────────────────────────────────────────────────

def _char_entropy(text: str) -> float:
    """Shannon entropy of the character distribution."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


# ──────────────────────────────────────────────────────────────────
# Multi-signal heuristics
# ──────────────────────────────────────────────────────────────────

_REPETITION_RE = re.compile(r"(.{4,})\1{3,}")  # any 4+ char block repeated 3+ times
_OVERLONG_TOKEN_RE = re.compile(r"\b\S{80,}\b")  # suspiciously long tokens

def _heuristic_evidence(text: str) -> list[Evidence]:
    """Return supplementary evidence from heuristic signals."""
    evidence: list[Evidence] = []
    normalized = text.lower()

    # Repetition attack (token flooding / ReDoS bait)
    if _REPETITION_RE.search(normalized):
        evidence.append(Evidence(
            source="heuristic", code="REPETITION_ATTACK",
            message="Unusual character/token repetition detected.",
            confidence=0.72, span=None,
        ))

    # Overlong single token (potential obfuscation)
    m = _OVERLONG_TOKEN_RE.search(text)
    if m:
        evidence.append(Evidence(
            source="heuristic", code="OVERLONG_TOKEN",
            message="Token of unusual length may be used for obfuscation.",
            confidence=0.65, span=m.group(0)[:40],
        ))

    # Very high entropy in a short message (randomised bypass attempt)
    if len(text) < 300 and _char_entropy(text) > 5.0:
        evidence.append(Evidence(
            source="heuristic", code="HIGH_ENTROPY",
            message="Unusually high character entropy in short message.",
            confidence=0.60, span=None,
        ))

    return evidence


# ──────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────

def detect_injection(text: str) -> DetectionResult:
    """
    Deterministic injection detector — no LLM on the hot path.

    Returns a DetectionResult with:
      - verdict: ALLOWED / FLAGGED / BLOCKED
      - threat_level: NONE / LOW / MEDIUM / HIGH / CRITICAL
      - evidence: list of matched signals
    """
    normalized = " ".join(text.lower().split())
    evidence: list[Evidence] = []
    max_confidence = 0.0

    # 1. Pattern matching
    for pattern, code, confidence in PATTERNS:
        match = re.search(pattern, normalized, flags=re.IGNORECASE)
        if match:
            max_confidence = max(max_confidence, confidence)
            evidence.append(Evidence(
                source="pattern",
                code=code,
                message=f"Matched injection signature: {code}.",
                confidence=confidence,
                span=match.group(0)[:120],
            ))

    # 2. Heuristic signals (supplement, don't decide alone)
    h_evidence = _heuristic_evidence(text)
    for e in h_evidence:
        if e.confidence > max_confidence * 0.85:   # only add if meaningful
            evidence.append(e)
            max_confidence = max(max_confidence, e.confidence)

    # 3. Verdict thresholds
    # Multiple mid-confidence hits escalate to BLOCKED
    high_hits = [e for e in evidence if (e.confidence or 0) >= 0.88]
    medium_hits = [e for e in evidence if 0.70 <= (e.confidence or 0) < 0.88]

    if max_confidence >= 0.93 or len(high_hits) >= 2:
        return DetectionResult(Verdict.BLOCKED, ThreatLevel.CRITICAL, evidence)
    if max_confidence >= 0.80 or (len(high_hits) == 1 and len(medium_hits) >= 1):
        return DetectionResult(Verdict.BLOCKED, ThreatLevel.HIGH, evidence)
    if max_confidence >= 0.70 or len(medium_hits) >= 2:
        return DetectionResult(Verdict.FLAGGED, ThreatLevel.MEDIUM, evidence)
    if evidence:  # low-confidence signals only
        return DetectionResult(Verdict.FLAGGED, ThreatLevel.LOW, evidence)

    return DetectionResult(Verdict.ALLOWED, ThreatLevel.NONE, [])
