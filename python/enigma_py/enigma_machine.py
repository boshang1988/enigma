"""Lightweight Enigma machine implementation in Python.

This mirrors the behaviour of the Go encoder package so the cracking tools
can reuse the same rotor/plugboard mechanics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

ROTOR_SUBS = [
    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "VZBRGITYUPSDNHLXAWMJQOFECK",
]

ROTOR_TURNS = ["Q", "E", "V", "J", "Z"]

REFLECTOR_UKWB = "YRUHQSLDPXNGOKMIEBFZCWVJAT"


@dataclass
class EnigmaSettings:
    rotor_order: List[int]
    ring_settings: List[int]
    plugs: str = ""
    reflector: str = REFLECTOR_UKWB


def _mod26(x: int) -> int:
    return x % 26


def _inc_letter(c: str, shift: int) -> str:
    return ALPHABET[_mod26(ALPHABET.index(c) + shift)]


class Rotor:
    def __init__(self, substitution: str, turnover: str) -> None:
        self.forward = [ALPHABET.index(c) for c in substitution]
        self.reverse = [0] * 26
        for i, c in enumerate(self.forward):
            self.reverse[c] = i
        self.turnover = ALPHABET.index(turnover)
        self.position = 0


class EnigmaMachine:
    def __init__(self, settings: EnigmaSettings) -> None:
        if len(settings.rotor_order) != 3 or len(settings.ring_settings) != 3:
            raise ValueError("Enigma requires exactly three rotors and ring settings.")
        self.settings = settings
        self.rotors = self._build_rotors(settings)
        self.reflector = [ALPHABET.index(c) for c in settings.reflector]
        self.plugboard = self._build_plugboard(settings.plugs)

    def _build_rotors(self, settings: EnigmaSettings) -> List[Rotor]:
        rotors: List[Rotor] = []
        for idx, rnum in enumerate(settings.rotor_order):
            ring_setting = settings.ring_settings[idx]
            if rnum < 1 or rnum > len(ROTOR_SUBS):
                raise ValueError("Rotor index must be between 1 and 5.")
            if ring_setting < 1 or ring_setting > 26:
                raise ValueError("Ring setting must be between 1 and 26.")

            sub = ROTOR_SUBS[rnum - 1]
            if ring_setting > 1:
                shift = ring_setting - 1
                sub = sub[-shift:] + sub[:-shift]
                sub = "".join(_inc_letter(c, shift) for c in sub)
            rotors.append(Rotor(substitution=sub, turnover=ROTOR_TURNS[rnum - 1]))
        return rotors

    def _build_plugboard(self, plugs: str) -> List[int]:
        mapping = list(range(26))
        for pair in (p for p in plugs.split(" ") if p):
            if len(pair) != 2:
                continue
            a = ALPHABET.index(pair[0])
            b = ALPHABET.index(pair[1])
            mapping[a], mapping[b] = b, a
        return mapping

    def reset(self, key: str) -> None:
        if len(key) != len(self.rotors):
            raise ValueError("Key must be three characters long.")
        for idx, letter in enumerate(key):
            self.rotors[idx].position = ALPHABET.index(letter)

    def encrypt(self, text: str) -> str:
        return "".join(self._encrypt_letter(c) for c in text if c.strip())

    def _encrypt_letter(self, letter: str) -> str:
        idx = ALPHABET.index(letter.upper())
        idx = self.plugboard[idx]

        self._step_rotors()

        for rotor in reversed(self.rotors):
            idx = _mod26(idx + rotor.position)
            idx = rotor.forward[idx]
            idx = _mod26(idx - rotor.position)

        idx = self.reflector[idx]

        for rotor in self.rotors:
            idx = _mod26(idx + rotor.position)
            idx = rotor.reverse[idx]
            idx = _mod26(idx - rotor.position)

        idx = self.plugboard[idx]
        return ALPHABET[idx]

    def _step_rotors(self) -> None:
        fast = self.rotors[2]
        mid = self.rotors[1]
        slow = self.rotors[0]

        if fast.position == fast.turnover:
            mid.position = _mod26(mid.position + 1)
        elif mid.position == mid.turnover:
            mid.position = _mod26(mid.position + 1)
            slow.position = _mod26(slow.position + 1)

        fast.position = _mod26(fast.position + 1)
