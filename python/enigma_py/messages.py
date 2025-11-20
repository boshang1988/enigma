"""Message preparation and encryption helpers."""

from __future__ import annotations

import random
from pathlib import Path
from typing import List, Sequence

from .enigma_machine import ALPHABET, EnigmaMachine, EnigmaSettings


PUNCTUATION_MAP = {
    ",": "ZZ",
    "?": "FRAQ",
    ".": "X",
    "!": "YUD",
    "&": "AND",
    "0": "ZERO",
    "1": "ONE",
    "2": "TWO",
    "3": "THREE",
    "4": "FOUR",
    "5": "FIVE",
    "6": "SIX",
    "7": "SEVEN",
    "8": "EIGHT",
    "9": "NINE",
}


def _normalize_words(words: Sequence[str]) -> str:
    joined = "".join(words).upper()
    for needle, repl in PUNCTUATION_MAP.items():
        joined = joined.replace(needle, repl)
    filtered = "".join(c for c in joined if c in ALPHABET)
    while len(filtered) % 5 != 0:
        filtered += "X"
    return filtered


def load_plaintext_lines(path: Path) -> List[str]:
    messages: List[str] = []
    start = False
    with path.open("r", encoding="utf8") as handle:
        for line in handle:
            if "***" in line:
                start = True
                continue
            if not start:
                continue
            msg = _normalize_words(line.strip().split())
            if msg:
                messages.append(msg)
    return messages


def random_key(rng: random.Random) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(3))


def encrypt_message(text: str, machine: EnigmaMachine, rng: random.Random) -> str:
    outer_key = random_key(rng)
    inner_key = random_key(rng)

    machine.reset(outer_key)
    encrypted_key = machine.encrypt(inner_key)

    machine.reset(inner_key)
    body = machine.encrypt(text + "XX")
    full = encrypted_key + body

    grouped = " ".join(full[i : i + 5] for i in range(0, len(full), 5))
    return f"{outer_key} {grouped}"


def encrypt_file(input_path: Path, output_path: Path, settings: EnigmaSettings, seed: int | None = None) -> None:
    rng = random.Random(seed)
    plaintexts = load_plaintext_lines(input_path)
    machine = EnigmaMachine(settings)

    encrypted = [encrypt_message(text, machine, rng) for text in plaintexts]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf8") as handle:
        for line in encrypted:
            handle.write(line + "\n")
