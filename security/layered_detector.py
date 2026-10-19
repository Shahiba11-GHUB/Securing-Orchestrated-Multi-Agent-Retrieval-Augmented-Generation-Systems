"""Layered prompt-injection detection for retrieved documents."""

import re
from .detector import detect_injection
from .regex_detector import detect_injection_regex

INSTRUCTION_PATTERNS = ['\\b(add|include|insert|integrate|mention)\\b.{0,100}\\b(answer|response|reply)\\b', '\\b(write|draft|compose|develop|provide)\\b.{0,100}\\b(story|poem|essay|speech|letter)\\b', '\\b(translate|translation)\\b.{0,100}\\b(to|into|french|spanish|english)\\b', '\\b(explain|describe|what is|who wrote|how do)\\b.{0,100}\\b(theory|capital|play|solar|war)\\b', '\\b(ignore|disregard|override)\\b.{0,100}\\b(instructions|rules|prompt)\\b']

def detect_instruction(text):
    matches = []

    for pattern in INSTRUCTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern)

    return {
        "is_suspicious": len(matches) > 0,
        "matched_patterns": matches
    }


def layered_detector(text, source=None, source_metadata=None):

    keyword = detect_injection(text)
    regex = detect_injection_regex(text)
    instruction = detect_instruction(text)

    suspicious = (
        keyword["is_suspicious"]
        or regex["is_suspicious"]
        or instruction["is_suspicious"]
    )

    matched_methods = []

    if keyword["is_suspicious"]:
        matched_methods.append("keyword")

    if regex["is_suspicious"]:
        matched_methods.append("regex")

    if instruction["is_suspicious"]:
        matched_methods.append("instruction")

    return {
        "is_suspicious": bool(suspicious),
        "risk_score": 1.0 if suspicious else 0.0,
        "decision": "quarantine" if suspicious else "allow",
        "reason": (
            "Matched: " + ", ".join(matched_methods)
            if suspicious
            else "No configured detection patterns matched"
        )
    }
