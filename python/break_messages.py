"""CLI to crack intercepted Enigma traffic using the Python Bombe."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Dict, List, Sequence

from enigma_py.cribs import COMMON_CRIBS, list_presets, resolve_cribs
from enigma_py.bombe import BombeResult, BombeSettings, make_key, run_bombe
from enigma_py.enigma_machine import EnigmaMachine, EnigmaSettings
from enigma_py.menu import make_menus


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Break Enigma messages with a crib and the Bombe.")
    parser.add_argument("--cipher-file", type=Path, required=True, help="Path to ciphertext file to break.")
    parser.add_argument(
        "--crib",
        action="append",
        help="Known plaintext crib to anchor menus (can be supplied multiple times).",
    )
    parser.add_argument(
        "--crib-preset",
        action="append",
        choices=sorted(COMMON_CRIBS.keys()),
        help="Use a preset crib drawn from common real-world traffic.",
    )
    parser.add_argument(
        "--use-all-common-cribs",
        action="store_true",
        help="Try every built-in preset crib (slower, but helpful when the crib is uncertain).",
    )
    parser.add_argument(
        "--list-crib-presets",
        action="store_true",
        help="List preset cribs and exit.",
    )
    parser.add_argument("--rotor-order", action="append", help="Limit rotor orders (e.g. 123). Can be repeated.")
    parser.add_argument("--min-menu-size", type=int, default=8, help="Ignore menus with fewer letters.")
    parser.add_argument("--max-menus", type=int, default=4, help="Upper bound on menus to try per message.")
    parser.add_argument("--workers", type=int, default=max(os.cpu_count() or 1, 1), help="Parallel workers for rotor orders.")
    parser.add_argument("--ring-settings", default="1 1 1", help="Ringstellung to use when decrypting recovered settings.")
    return parser.parse_args()


def load_messages(path: Path) -> List[Dict[str, str]]:
    messages: List[Dict[str, str]] = []
    with path.open("r", encoding="utf8") as handle:
        for line in handle:
            compact = "".join(line.strip().split())
            if len(compact) < 6:
                continue
            messages.append(
                {
                    "outer_key": compact[:3],
                    "encrypted_key": compact[3:6],
                    "ciphertext": compact[6:],
                    "raw": line.strip(),
                }
            )
    return messages


def parse_rotor_orders(raw_orders: Sequence[str] | None) -> List[List[int]]:
    if not raw_orders:
        return []
    parsed: List[List[int]] = []
    for order in raw_orders:
        if len(order) != 3 or not order.isdigit():
            continue
        parsed.append([int(order[0]), int(order[1]), int(order[2])])
    return parsed


def decrypt_with_result(result: BombeResult, ring_settings: List[int]) -> str:
    settings = EnigmaSettings(
        rotor_order=list(reversed(result.rotors)),
        ring_settings=ring_settings,
        plugs=result.plugboard,
    )
    machine = EnigmaMachine(settings)
    machine.reset(make_key(result.offset))
    return machine.encrypt(result.message)


def print_presets() -> None:
    print("Built-in crib presets (use with --crib-preset or --use-all-common-cribs):")
    for preset in list_presets():
        print(f"  {preset.key:18s} {preset.text:>28s}  - {preset.rationale}")


def main() -> None:
    args = parse_args()
    if args.list_crib_presets:
        print_presets()
        return

    cribs = resolve_cribs(args.crib, args.crib_preset, args.use_all_common_cribs)
    if not cribs:
        raise SystemExit("Provide at least one crib via --crib or select a preset crib.")

    messages = load_messages(args.cipher_file)
    rotor_orders = parse_rotor_orders(args.rotor_order)
    ring_settings = [int(x) for x in args.ring_settings.split()]

    for midx, msg in enumerate(messages):
        print(f"\n--- Message {midx + 1}: {msg['raw']} ---")
        for cidx, crib in enumerate(cribs):
            print(f"\nCrib {cidx + 1}/{len(cribs)}: {crib}")
            menus = make_menus(msg["ciphertext"], crib)
            menus = [m for m in menus if m.num_letters >= args.min_menu_size]
            menus = sorted(menus, key=lambda m: m.num_letters, reverse=True)[: args.max_menus]
            if not menus:
                print("No viable menus found; try a different crib.")
                continue

            for mid, menu in enumerate(menus):
                print(f"\nMenu {mid + 1}/{len(menus)} with {menu.num_letters} letters and {len(menu.connections)} edges")
                settings = BombeSettings(connections=menu.connections, num_letters=menu.num_letters)
                result_count = 0
                for res in run_bombe(
                    message=msg["ciphertext"],
                    settings=settings,
                    rotor_orders=rotor_orders if rotor_orders else None,
                    workers=args.workers,
                ):
                    plaintext = decrypt_with_result(res, ring_settings)
                    result_count += 1
                    print(f"\nRotor order {res.rotors}, offset {make_key(res.offset)}, plugboard {res.plugboard}")
                    print(plaintext)
                if result_count == 0:
                    print("No candidate settings surfaced for this menu.")


if __name__ == "__main__":
    main()
