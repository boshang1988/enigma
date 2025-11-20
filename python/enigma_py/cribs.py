"""Common Enigma crib phrases and helpers to resolve CLI crib options."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence


@dataclass(frozen=True)
class CribPreset:
    key: str
    text: str
    rationale: str


COMMON_CRIBS: Dict[str, CribPreset] = {
    "weather-short": CribPreset(
        key="weather-short",
        text="WETTER",
        rationale="Daily weather bulletins that appeared in Navy and Air Force traffic.",
    ),
    "weather-forecast": CribPreset(
        key="weather-forecast",
        text="WETTERVORHERSAGE",
        rationale="Longer weather forecast header that famously seeded early Bombe runs.",
    ),
    "salutation": CribPreset(
        key="salutation",
        text="HEILHITLER",
        rationale="Standardized sign-off that leaked predictable plaintext.",
    ),
    "no-events": CribPreset(
        key="no-events",
        text="KEINEBESONDERENEREIGNISSE",
        rationale="Routine status phrase for uneventful reports.",
    ),
    "command-routing": CribPreset(
        key="command-routing",
        text="OBERKOMMANDO",
        rationale="High-command routing keyword common in operational traffic.",
    ),
}


def list_presets() -> List[CribPreset]:
    return list(COMMON_CRIBS.values())


def resolve_cribs(
    explicit: Sequence[str] | None,
    preset_keys: Sequence[str] | None,
    include_all: bool = False,
) -> List[str]:
    """Return normalized crib strings from user input and presets."""

    def _normalize(value: str) -> str:
        return "".join(value.split()).upper()

    seen = set()
    cribs: List[str] = []

    for raw in explicit or []:
        crib = _normalize(raw)
        if crib and crib not in seen:
            seen.add(crib)
            cribs.append(crib)

    if preset_keys:
        for key in preset_keys:
            preset = COMMON_CRIBS.get(key)
            if preset:
                crib = _normalize(preset.text)
                if crib and crib not in seen:
                    seen.add(crib)
                    cribs.append(crib)

    if include_all:
        for preset in COMMON_CRIBS.values():
            crib = _normalize(preset.text)
            if crib and crib not in seen:
                seen.add(crib)
                cribs.append(crib)

    return cribs
