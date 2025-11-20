"""Plugboard validation matching the Go checker package."""

from __future__ import annotations

from typing import Dict, Set, Tuple


State = Dict[int, Dict[int, bool]]


def check_possible_plugboard(state: State) -> Tuple[str, bool]:
    one_lit, all_but_one = _how_many_lit(state)
    if (one_lit and all_but_one) or (not one_lit and not all_but_one):
        return "", False

    steckers: Dict[int, int] = {}
    pair_count = 0
    self_count = 0
    plugboard = []

    if one_lit:
        for k, mapping in state.items():
            for target in mapping:
                low, high = sorted((k, target))
                if low in steckers and steckers[low] != high:
                    return "", False
                if low not in steckers:
                    steckers[low] = high
                    if low == high:
                        self_count += 1
                    else:
                        pair_count += 1
                    plugboard.append(f"{chr(low + 65)}{chr(high + 65)}")
    else:
        for k, mapping in state.items():
            all_states = {i: True for i in range(26)}
            for target in mapping:
                all_states.pop(target, None)
            for target in all_states:
                low, high = sorted((k, target))
                if low in steckers and steckers[low] != high:
                    return "", False
                if low not in steckers:
                    steckers[low] = high
                    if low == high:
                        self_count += 1
                    else:
                        pair_count += 1
                    plugboard.append(f"{chr(low + 65)}{chr(high + 65)}")

    valid = pair_count <= 10 and self_count <= 6
    return " ".join(plugboard), valid


def _how_many_lit(state: State) -> Tuple[bool, bool]:
    one_lit = False
    all_but_one = False
    for mapping in state.values():
        if len(mapping) == 1:
            one_lit = True
        elif len(mapping) == 25:
            all_but_one = True
        else:
            return False, False
    return one_lit, all_but_one
