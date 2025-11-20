"""Menu construction from ciphertext and crib."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Menu:
    connections: List[str] = field(default_factory=list)
    num_letters: int = 0
    graph: Dict[str, Dict[str, int]] = field(default_factory=dict)


def make_menus(ciphertext: str, crib: str) -> List[Menu]:
    menus: List[Menu] = []
    cipher = ciphertext.upper()
    crib = crib.upper()
    for start in range(0, len(cipher) - len(crib) + 1):
        window = cipher[start : start + len(crib)]
        ok, menu = _make_menu(start, window, crib)
        if ok:
            menus.append(menu)
    return menus


def _make_menu(start: int, fragment: str, crib: str) -> tuple[bool, Menu]:
    menu = Menu()
    for idx, cipher_char in enumerate(fragment):
        if cipher_char == crib[idx]:
            return False, menu
        _add_connection(menu, cipher_char, crib[idx], start + idx)
    _reformat(menu, crib)
    return True, menu


def _add_connection(menu: Menu, a: str, b: str, pos: int) -> None:
    menu.graph.setdefault(a, {})[b] = pos
    menu.graph.setdefault(b, {})[a] = pos


def _reformat(menu: Menu, crib: str) -> None:
    main_component: List[str] = []
    visited: Dict[str, bool] = {}

    for char in crib:
        if char in visited:
            continue
        queue = [char]
        component: List[str] = []
        visited[char] = True
        while queue:
            current = queue.pop(0)
            component.append(current)
            for neighbour in menu.graph.get(current, {}):
                if neighbour not in visited:
                    visited[neighbour] = True
                    queue.append(neighbour)
        if len(component) > len(main_component):
            main_component = component

    menu.num_letters = 0
    for a in main_component:
        menu.num_letters += 1
        for b, pos in menu.graph.get(a, {}).items():
            if a < b:
                menu.connections.append(f"{a}{b}{pos + 1}")
