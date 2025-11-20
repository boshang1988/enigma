"""Break every ciphertext file in a directory with a single invocation."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Sequence

from enigma_py.cribs import COMMON_CRIBS, list_presets, resolve_cribs
from enigma_py.bombe import BombeSettings, make_key, run_bombe
from enigma_py.enigma_machine import EnigmaMachine, EnigmaSettings
from enigma_py.menu import make_menus
from break_messages import load_messages, parse_rotor_orders


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Bombe against all ciphertext files in a directory.")
    parser.add_argument("--cipher-dir", type=Path, required=True, help="Directory of ciphertext files to process.")
    parser.add_argument(
        "--crib",
        action="append",
        help="Known plaintext crib (can be supplied multiple times).",
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
    parser.add_argument("--workers", type=int, default=4, help="Parallel workers per rotor order.")
    parser.add_argument("--ring-settings", default="1 1 1", help="Ringstellung to use when decrypting recovered settings.")
    return parser.parse_args()


def decrypt_with_result(result, ring_settings: List[int]) -> str:
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


def break_file(
    path: Path,
    cribs: Sequence[str],
    rotor_orders: Sequence[List[int]] | None,
    min_menu: int,
    max_menus: int,
    workers: int,
    ring_settings: List[int],
) -> None:
    messages = load_messages(path)
    print(f"\n==== {path} ({len(messages)} intercepted messages) ====")

    for midx, msg in enumerate(messages):
        print(f"\n--- Message {midx + 1}: {msg['raw']} ---")
        for cidx, crib in enumerate(cribs):
            print(f"\nCrib {cidx + 1}/{len(cribs)}: {crib}")
            menus = make_menus(msg["ciphertext"], crib)
            menus = [m for m in menus if m.num_letters >= min_menu]
            menus = sorted(menus, key=lambda m: m.num_letters, reverse=True)[:max_menus]
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
                    workers=workers,
                ):
                    plaintext = decrypt_with_result(res, ring_settings)
                    result_count += 1
                    print(f"\nRotor order {res.rotors}, offset {make_key(res.offset)}, plugboard {res.plugboard}")
                    print(plaintext)
                if result_count == 0:
                    print("No candidate settings surfaced for this menu.")


def main() -> None:
    args = parse_args()
    if args.list_crib_presets:
        print_presets()
        return

    rotor_orders = parse_rotor_orders(args.rotor_order)
    ring_settings = [int(x) for x in args.ring_settings.split()]
    cribs = resolve_cribs(args.crib, args.crib_preset, args.use_all_common_cribs)
    if not cribs:
        raise SystemExit("Provide at least one crib via --crib or select a preset crib.")

    files = sorted(p for p in args.cipher_dir.iterdir() if p.is_file())
    if not files:
        raise SystemExit(f"No ciphertext files found in {args.cipher_dir}")

    for fpath in files:
        break_file(
            path=fpath,
            cribs=cribs,
            rotor_orders=rotor_orders,
            min_menu=args.min_menu_size,
            max_menus=args.max_menus,
            workers=args.workers,
            ring_settings=ring_settings,
        )


if __name__ == "__main__":
    main()
