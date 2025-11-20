from __future__ import annotations

import itertools
import string
from pathlib import Path
from typing import Dict, Iterable, Iterator, Sequence

DEFAULT_CHARSETS: Dict[str, str] = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~",
    "a": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~",
    "h": "0123456789abcdef",
}


def mutate_word(word: str, mode: str = "simple") -> Iterator[str]:
    token = word.strip()
    if not token:
        return

    seen = set()
    forms = {token, token.lower(), token.upper(), token.title()}
    suffixes = ["", "1", "!", "123", "2024", "2025"]
    if mode == "none":
        suffixes = [""]

    def emit(form: str) -> Iterator[str]:
        for suffix in suffixes:
            candidate = f"{form}{suffix}"
            if candidate not in seen:
                seen.add(candidate)
                yield candidate
        for digit in range(10):
            candidate = f"{form}{digit}"
            if candidate not in seen:
                seen.add(candidate)
                yield candidate

    for base in forms:
        yield from emit(base)

    if mode == "aggressive":
        leet_map = {"a": ["4", "@"], "e": ["3"], "i": ["1"], "o": ["0"], "s": ["5", "$"], "t": ["7"], "l": ["1"]}
        for base in list(forms):
            lower = base.lower()
            for idx, char in enumerate(lower):
                if char not in leet_map:
                    continue
                for replacement in leet_map[char]:
                    mutated = lower[:idx] + replacement + lower[idx + 1 :]
                    if mutated not in seen:
                        seen.add(mutated)
                        yield from emit(mutated)


def wordlist_candidates(paths: Sequence[str], mutate_mode: str = "simple") -> Iterator[str]:
    for raw_path in paths:
        path = Path(raw_path)
        with path.open("r", encoding="utf8", errors="ignore") as handle:
            for line in handle:
                for candidate in mutate_word(line.strip(), mode=mutate_mode):
                    yield candidate


def parse_mask(mask: str, charsets: Dict[str, str]) -> Sequence[Sequence[str]]:
    tokens = []
    idx = 0
    while idx < len(mask):
        char = mask[idx]
        if char == "?" and idx + 1 < len(mask):
            key = mask[idx + 1]
            if key not in charsets:
                raise ValueError(f"Unknown mask charset '?{key}'")
            tokens.append(list(charsets[key]))
            idx += 2
        else:
            tokens.append([char])
            idx += 1
    return tokens


def mask_candidates(mask: str, charsets: Dict[str, str]) -> Iterable[str]:
    tokens = parse_mask(mask, charsets)
    for combo in itertools.product(*tokens):
        yield "".join(combo)


def append_mask_candidates(
    word_paths: Sequence[str],
    mask: str,
    charsets: Dict[str, str],
    mutate_mode: str = "simple",
) -> Iterable[str]:
    for word in wordlist_candidates(word_paths, mutate_mode=mutate_mode):
        for suffix in mask_candidates(mask, charsets):
            yield f"{word}{suffix}"
