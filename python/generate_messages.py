"""Batch encryption helper to mirror the original Go make_messages tool."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from enigma_py.enigma_machine import EnigmaSettings
from enigma_py.messages import encrypt_file


DEFAULT_SETTINGS = EnigmaSettings(
    rotor_order=[5, 1, 2],
    ring_settings=[14, 4, 12],
    plugs="AN IV LH YP WM TR XU FO ZB ED",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt plaintext files with Enigma settings.")
    parser.add_argument("--input", type=Path, default=Path("messages/plaintext"), help="Plaintext file or directory.")
    parser.add_argument("--output-dir", type=Path, default=Path("messages/ciphertext"), help="Where to write ciphertext.")
    parser.add_argument("--rotors", default="5 1 2", help="Rotor order, space separated (e.g. '1 2 3').")
    parser.add_argument("--rings", default="14 4 12", help="Ring settings, space separated.")
    parser.add_argument("--plugs", default=DEFAULT_SETTINGS.plugs, help="Plugboard pairs separated by space.")
    parser.add_argument("--seed", type=int, default=None, help="Optional seed for deterministic output.")
    return parser.parse_args()


def parse_ints(raw: str) -> List[int]:
    return [int(x) for x in raw.split()]


def collect_inputs(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    return sorted([p for p in path.iterdir() if p.is_file()])


def main() -> None:
    args = parse_args()
    settings = EnigmaSettings(
        rotor_order=parse_ints(args.rotors),
        ring_settings=parse_ints(args.rings),
        plugs=args.plugs,
    )

    inputs = collect_inputs(args.input)
    if not inputs:
        raise SystemExit("No plaintext files found.")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    for input_path in inputs:
        output_path = args.output_dir / input_path.name
        encrypt_file(input_path, output_path, settings=settings, seed=args.seed)
        print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
