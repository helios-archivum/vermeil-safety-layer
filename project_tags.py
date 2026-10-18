"""Deterministic project tagger for Hindsight auto-retain.

Used by _make_turn_retain_job so every automatically retained turn carries a
project tag without any LLM call. Classification is keyword-driven and cheap;
a turn matching nothing gets NO project tag (never a synthetic 'general') so
recall's tags_match='any' (which includes untagged memories) never hides it.

Project list is the known universe; extend it when a new long-lived project
appears. Keywords are matched case-insensitively against the raw turn text
(both speakers), longest-keyword-first so 'ark ascended' beats 'ark'.
"""

from __future__ import annotations

import re
from typing import List, Optional

# project -> ranked keyword patterns (regex, case-insensitive, word-ish boundary)
# Order inside a list does not matter; the FIRST project with any hit wins,
# evaluated in _PROJECT_PRIORITY order so overlapping domains resolve sensibly.
_PROJECT_KEYWORDS: dict[str, list[str]] = {
    "ark": [
        r"ark(?!\s*(?:-|\bserver\b))", r"ark\s*ascended", r"asa\b",
        r"curseforge", r"bcml", r"mods?\s+de\s+ark", r"servidor\s+dedicado\s+ark",
    ],
    "memoria": [
        r"\bhindsight\b", r"memoria\b", r"retain\b", r"recall\b", r"consolidaci[oó]n",
        r"pg0", r"cyber-?tiel", r"is_trivial_prompt", r"bank\b", r"invalidat\w+\s+memor",
    ],
    "providers": [
        r"\bproviders?\b", r"api\s*key", r"\bnvidia\b", r"\bgroq\b", r"\bglm\b",
        r"\bapinex\b", r"\bminimax\b", r"\bdeepseek\b", r"\bmercury\b",
        r"rate\s*limit", r"free\s*tier", r"\bEOL\b", r"check-?in",
    ],
    "cemu": [
        r"\bcemu\b", r"\bwiiu\b", r"\bwii\s*u\b", r"emulador", r"super\s*\+\s*r",
    ],
    "hardware": [
        r"\bnas\b", r"\bhdd\b", r"\bssd\b", r"\bvr?ram\b", r"\bnvidia-smi\b",
        r"lm\s*studio", r"partici[oó]n\s+de\s+windows", r"\b8tb\b", r"\b1tb\b",
        r"samba", r"/mnt/", r"sonido", r"bocinas", r"\btele\b",
    ],
    "hyprland": [
        r"hyprland", r"wayland", r"waybar", r"cachyos", r"\bpacman\b",
        r"\bproton\b", r"\bwine\b", r"\btmux\b",
    ],
    "hermes": [
        r"\bhermes\b", r"\bgateway\b", r"config\.yaml", r"\bsoul\.md\b",
        r"\bskills?\b", r"\bplugins?\b", r"delegate_task", r"subagent\w*",
        r"\bmcps?\b", r"cron(?:job)?\b", r"prompt\s*cach\w*",
    ],
}

# Projects evaluated in this order: the first that matches wins. This resolves
# overlap (e.g. a turn about LM Studio memory is 'memoria', not 'hardware').
_PROJECT_PRIORITY: List[str] = [
    "memoria",
    "providers",
    "ark",
    "cemu",
    "hyprland",
    "hardware",
    "hermes",
]

_TAG_PREFIX = "project:"

# Pre-compile once (module import), reuse forever.
_COMPILED: dict[str, list[re.Pattern]] = {
    proj: [re.compile(p, re.IGNORECASE) for p in pats]
    for proj, pats in _PROJECT_KEYWORDS.items()
}


def classify_project(text: Optional[str]) -> Optional[str]:
    """Return the project name for *text*, or None when nothing matches.

    None is deliberate: an untagged memory still surfaces under
    tags_match='any' (OR includes untagged), so classification failure never
    hides the memory.
    """
    if not text:
        return None
    haystack = str(text)
    for proj in _PROJECT_PRIORITY:
        pats = _COMPILED.get(proj)
        if not pats:
            continue
        for pat in pats:
            if pat.search(haystack):
                return proj
    return None


def project_tags(text: Optional[str]) -> List[str]:
    """Tag list for auto-retain: ['project:<name>'] or [] when unmatched."""
    proj = classify_project(text)
    return [f"{_TAG_PREFIX}{proj}"] if proj else []
