"""Python port of the simplified Bombe implementation from the Go code."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .checker import check_possible_plugboard


CONST_ROTORS: List[List[int]] = [
    [4, 10, 12, 5, 11, 6, 3, 16, 21, 25, 13, 19, 14, 22, 24, 7, 23, 20, 18, 15, 0, 8, 1, 17, 2, 9],
    [0, 9, 3, 10, 18, 8, 17, 20, 23, 1, 11, 7, 22, 19, 12, 2, 16, 6, 25, 13, 15, 24, 5, 21, 14, 4],
    [1, 3, 5, 7, 9, 11, 2, 15, 17, 19, 23, 21, 25, 13, 24, 4, 8, 22, 6, 0, 10, 12, 20, 18, 16, 14],
    [4, 18, 14, 21, 15, 25, 9, 0, 24, 16, 20, 8, 17, 7, 23, 11, 13, 5, 19, 6, 10, 3, 2, 12, 22, 1],
    [21, 25, 1, 17, 6, 8, 19, 24, 20, 15, 18, 3, 13, 7, 11, 23, 0, 22, 12, 9, 16, 14, 5, 4, 2, 10],
]

ROTOR_ORDERS: List[List[int]] = [
    [1, 2, 3], [1, 3, 2], [2, 1, 3], [2, 3, 1], [3, 1, 2], [3, 2, 1],
    [1, 2, 4], [1, 4, 2], [2, 1, 4], [2, 4, 1], [4, 1, 2], [4, 2, 1],
    [1, 2, 5], [1, 5, 2], [2, 1, 5], [2, 5, 1], [5, 1, 2], [5, 2, 1],
    [1, 3, 4], [1, 4, 3], [3, 1, 4], [3, 4, 1], [4, 1, 3], [4, 3, 1],
    [1, 3, 5], [1, 5, 3], [3, 1, 5], [3, 5, 1], [5, 1, 3], [5, 3, 1],
    [1, 4, 5], [1, 5, 4], [4, 1, 5], [4, 5, 1], [5, 1, 4], [5, 4, 1],
    [2, 3, 4], [2, 4, 3], [3, 2, 4], [3, 4, 2], [4, 2, 3], [4, 3, 2],
    [2, 3, 5], [2, 5, 3], [3, 2, 5], [3, 5, 2], [5, 2, 3], [5, 3, 2],
    [2, 4, 5], [2, 5, 4], [4, 2, 5], [4, 5, 2], [5, 2, 4], [5, 4, 2],
    [3, 4, 5], [3, 5, 4], [4, 3, 5], [4, 5, 3], [5, 3, 4], [5, 4, 3],
]

UKWB = [24, 17, 20, 7, 16, 18, 11, 3, 15, 23, 13, 6, 14, 10, 12, 8, 4, 1, 5, 25, 2, 22, 21, 9, 0, 19]


@dataclass
class BombeSettings:
    connections: List[str]
    num_letters: int
    rotor_order: Optional[List[int]] = None


@dataclass
class BombeResult:
    offset: int
    rotors: List[int]
    printable: str
    state: Dict[int, Dict[int, bool]]
    message: str
    plugboard: str = ""


class Bombe:
    def __init__(self, settings: BombeSettings, rotor_order: List[int], precompute: bool = True) -> None:
        self.settings = settings
        self.rotor_order = rotor_order
        self.rotors = [CONST_ROTORS[i - 1] for i in rotor_order]
        self.transform_cache: Optional[List[List[int]]] = None
        if precompute:
            self.transform_cache = [self._make_transform(offset) for offset in range(26 ** 3)]

    def run(self, message: str) -> List[BombeResult]:
        results: List[BombeResult] = []
        for offset in range(26 ** 3):
            connections, state = self._make_system(offset)
            start = self._initialize(state)
            self._find_steady_state(start, connections, state)
            if _test_output(state):
                results.append(
                    BombeResult(
                        offset=offset,
                        rotors=self.rotor_order,
                        printable=_format_output(state),
                        state=state,
                        message=message,
                    )
                )
        return results

    def _make_transform(self, offset: int) -> List[int]:
        offsets = [offset % 26, (offset % (26 * 26)) // 26, offset // (26 * 26)]
        transform = [0] * 26
        for i in range(26):
            transform[i] = self._encrypt_letter(i, offsets)
        return transform

    def _encrypt_letter(self, letter: int, offsets: Sequence[int]) -> int:
        idx = letter
        for rotor_idx in range(3):
            idx = _mod26(idx + offsets[rotor_idx])
            idx = self.rotors[rotor_idx][idx]
            idx = _mod26(idx - offsets[rotor_idx])
        idx = UKWB[idx]
        for rotor_idx in reversed(range(3)):
            idx = _mod26(idx + offsets[rotor_idx])
            idx = self.rotors[rotor_idx].index(idx)
            idx = _mod26(idx - offsets[rotor_idx])
        return idx

    def _make_system(self, offset: int) -> Tuple[Dict[int, List[Tuple[List[int], Tuple[int, int]]]], Dict[int, Dict[int, bool]]]:
        connections: Dict[int, List[Tuple[List[int], Tuple[int, int]]]] = {}
        state: Dict[int, Dict[int, bool]] = {}
        for conn in self.settings.connections:
            n1 = ord(conn[0]) - 65
            n2 = ord(conn[1]) - 65
            off = int(conn[2:])
            state.setdefault(n1, {})
            state.setdefault(n2, {})
            connections.setdefault(n1, [])
            connections.setdefault(n2, [])

            cached = (
                self.transform_cache[(off + offset) % (26 ** 3)]
                if self.transform_cache is not None
                else self._make_transform(off + offset)
            )
            connections[n1].append((cached, (n1, n2)))
            connections[n2].append((cached, (n1, n2)))
        return connections, state

    def _initialize(self, state: Dict[int, Dict[int, bool]]) -> int:
        for key in state:
            state[key][key] = True
            return key
        raise ValueError("state cannot be empty")

    def _find_steady_state(
        self,
        start: int,
        connections: Dict[int, List[Tuple[List[int], Tuple[int, int]]]],
        state: Dict[int, Dict[int, bool]],
    ) -> None:
        queue = [start]
        while queue:
            elem = queue.pop(0)
            for transform, endpoints in connections[elem]:
                for endp in endpoints:
                    if endp == elem:
                        continue
                    new_state = _transform(state[elem], transform)
                    if not _same(state[endp], new_state):
                        for k in new_state:
                            state[endp][k] = True
                        if endp not in queue:
                            queue.append(endp)
            new_nodes, state = _diagonal_board(state)
            for node in new_nodes:
                if node not in queue:
                    queue.append(node)


def _transform(input_map: Dict[int, bool], transform: List[int]) -> Dict[int, bool]:
    return {transform[k]: True for k in input_map}


def _same(m1: Dict[int, bool], m2: Dict[int, bool]) -> bool:
    if len(m1) != len(m2):
        return False
    for key, val in m1.items():
        if m2.get(key) != val:
            return False
    for key, val in m2.items():
        if m1.get(key) != val:
            return False
    return True


def _diagonal_board(state: Dict[int, Dict[int, bool]]) -> Tuple[List[int], Dict[int, Dict[int, bool]]]:
    out: Dict[int, Dict[int, bool]] = {k: {} for k in state}
    to_check: List[int] = []
    for k, mapping in state.items():
        for k2 in mapping:
            out[k][k2] = True
            if k2 in state and k not in state[k2]:
                out[k2][k] = True
                to_check.append(k2)
    return to_check, out


def _format_output(state: Dict[int, Dict[int, bool]]) -> str:
    lines = []
    for pt, mapping in state.items():
        letters = [chr(i + 65) for i in range(26)]
        for ct in mapping:
            letters[ct] = "_"
        lines.append("".join(letters) + f" <- {chr(pt + 65)!r}")
    return "\n".join(lines)


def _test_output(state: Dict[int, Dict[int, bool]]) -> bool:
    count = sum(len(m) for m in state.values())
    return count < 26 * len(state)


def _mod26(x: int) -> int:
    return x % 26


def make_key(offset: int) -> str:
    high = offset // (26 * 26)
    med = (offset // 26) % 26
    low = offset % 26
    return "".join(chr(x + 65) for x in (high, med, low))


def run_bombe(
    message: str,
    settings: BombeSettings,
    rotor_orders: Optional[Sequence[List[int]]] = None,
    workers: Optional[int] = None,
    precompute: bool = True,
) -> Iterable[BombeResult]:
    orders = list(rotor_orders) if rotor_orders else ( [settings.rotor_order] if settings.rotor_order else ROTOR_ORDERS )

    tasks = []
    if workers and workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            for order in orders:
                tasks.append(executor.submit(_run_single_order, message, settings, order, precompute))
            for fut in as_completed(tasks):
                for res in fut.result():
                    yield res
    else:
        for order in orders:
            for res in _run_single_order(message, settings, order, precompute):
                yield res


def _run_single_order(
    message: str,
    settings: BombeSettings,
    rotor_order: List[int],
    precompute: bool,
) -> List[BombeResult]:
    bombe = Bombe(settings=settings, rotor_order=rotor_order, precompute=precompute)
    raw_results = bombe.run(message)
    filtered: List[BombeResult] = []
    for res in raw_results:
        plugboard, ok = check_possible_plugboard(res.state)
        if ok:
            res.plugboard = plugboard
            filtered.append(res)
    return filtered
