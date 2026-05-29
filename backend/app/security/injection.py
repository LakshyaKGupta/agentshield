from __future__ import annotations

import re
from dataclasses import dataclass

from ..contracts import Evidence, ThreatLevel, Verdict


@dataclass(frozen=True)
class DetectionResult:
    verdict: Verdict
    threat_level: ThreatLevel
    evidence: list[Evidence]


PATTERNS: list[tuple[str, str, float]] = [
    (r"ignore (all )?(previous|prior|above) instructions?", "INSTRUCTION_OVERRIDE", 0.96),
    (r"(disregard|forget|override) (your )?(system |safety |previous )?prompt", "PROMPT_OVERRIDE", 0.94),
    (r"print (your )?(system |full )?prompt", "PROMPT_EXFILTRATION", 0.93),
    (r"reveal (your )?(instructions|prompt|training)", "SECRET_EXFILTRATION", 0.92),
    (r"\[SYSTEM\]|\[INST\]|<\|system\|>", "SYSTEM_TOKEN_INJECTION", 0.88),
    (r"jailbreak|DAN mode|developer mode", "JAILBREAK", 0.9),
    (r"you are now (a|an|the)?\s*\w+", "ROLE_HIJACK", 0.82),
    (r"act as (if|though|a|an)", "ROLE_PLAY_BYPASS", 0.72),
]


def detect_injection(text: str) -> DetectionResult:
    normalized = " ".join(text.lower().split())
    evidence: list[Evidence] = []
    max_confidence = 0.0
    for pattern, code, confidence in PATTERNS:
        match = re.search(pattern, normalized, flags=re.IGNORECASE)
        if match:
            max_confidence = max(max_confidence, confidence)
            evidence.append(
                Evidence(
                    source="pattern",
                    code=code,
                    message="Prompt injection signature matched.",
                    confidence=confidence,
                    span=match.group(0),
                )
            )
    if max_confidence >= 0.9:
        return DetectionResult(Verdict.BLOCKED, ThreatLevel.CRITICAL, evidence)
    if max_confidence >= 0.7:
        return DetectionResult(Verdict.FLAGGED, ThreatLevel.MEDIUM, evidence)
    return DetectionResult(Verdict.ALLOWED, ThreatLevel.NONE, [])

