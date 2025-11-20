from __future__ import annotations

import argparse
import itertools
import sys
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple

from .attacks import DEFAULT_CHARSETS, append_mask_candidates, mask_candidates, wordlist_candidates
from .core import HashTarget, format_match, load_hashes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hashcat-like cracking toolkit for modern hashes.")
    parser.add_argument("--hash", action="append", dest="hashes", default=[], help="Hash entry (can be repeated).")
    parser.add_argument(
        "--hash-file",
        action="append",
        dest="hash_files",
        default=[],
        help="File containing hashes (one per line, comments with #).",
    )
    parser.add_argument(
        "--algorithm",
        help="Default algorithm when hashes omit an explicit prefix (md5/sha256/sha3-512/etc).",
    )
    parser.add_argument(
        "--salt-position",
        choices=["prefix", "suffix"],
        default="prefix",
        help="Position of salt for simple digests when provided separately (default: prefix).",
    )
    parser.add_argument(
        "--wordlist",
        action="append",
        dest="wordlists",
        default=[],
        help="Path to a wordlist for dictionary attacks (can be repeated).",
    )
    parser.add_argument(
        "--mask",
        action="append",
        dest="masks",
        default=[],
        help="Mask pattern using Hashcat-style tokens (e.g. ?u?l?l?d for an uppercase + lowercase + digits mix).",
    )
    parser.add_argument(
        "--append-mask",
        help="Hybrid attack: append a mask onto every wordlist candidate (e.g. '?d?d' to add two digits).",
    )
    parser.add_argument(
        "--mutate",
        choices=["none", "simple", "aggressive"],
        default="simple",
        help="Dictionary mutation level (case flips, digits, symbols, and optional leetspeak).",
    )
    parser.add_argument(
        "--charset-lower",
        help="Override characters used for ?l in masks.",
    )
    parser.add_argument(
        "--charset-upper",
        help="Override characters used for ?u in masks.",
    )
    parser.add_argument(
        "--charset-digit",
        help="Override characters used for ?d in masks.",
    )
    parser.add_argument(
        "--charset-symbol",
        help="Override characters used for ?s in masks.",
    )
    parser.add_argument(
        "--status-every",
        type=int,
        default=50000,
        help="Print a progress heartbeat after this many candidates (0 to disable).",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        help="Optional ceiling on candidates to try before stopping.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Keep running even after every hash in the set is cracked.",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read candidate passwords from stdin (one per line) as an additional attack source.",
    )
    return parser.parse_args()


def build_charsets(args: argparse.Namespace) -> Dict[str, str]:
    charsets = dict(DEFAULT_CHARSETS)
    if args.charset_lower:
        charsets["l"] = args.charset_lower
    if args.charset_upper:
        charsets["u"] = args.charset_upper
    if args.charset_digit:
        charsets["d"] = args.charset_digit
    if args.charset_symbol:
        charsets["s"] = args.charset_symbol
    charsets["a"] = charsets["l"] + charsets["u"] + charsets["d"] + charsets["s"]
    return charsets


def candidate_stream(args: argparse.Namespace, charsets: Dict[str, str]) -> Iterator[str]:
    streams: List[Iterable[str]] = []

    if args.wordlists:
        streams.append(wordlist_candidates(args.wordlists, mutate_mode=args.mutate))
    if args.append_mask:
        if not args.wordlists:
            raise ValueError("--append-mask requires at least one --wordlist.")
        streams.append(append_mask_candidates(args.wordlists, args.append_mask, charsets, mutate_mode=args.mutate))
    for mask in args.masks:
        streams.append(mask_candidates(mask, charsets))
    if args.stdin:
        streams.append((line.strip() for line in sys.stdin if line.strip()))

    if not streams:
        raise ValueError("Select at least one attack source (--wordlist, --mask, --append-mask, or --stdin).")

    return itertools.chain.from_iterable(streams)


def crack(
    targets: Sequence[HashTarget],
    candidates: Iterable[str],
    status_every: int = 0,
    max_candidates: int | None = None,
    keep_going: bool = False,
) -> Tuple[List[Tuple[HashTarget, str]], int, int]:
    remaining = {idx: target for idx, target in enumerate(targets)}
    matches: List[Tuple[HashTarget, str]] = []
    tested = 0

    for candidate in candidates:
        tested += 1
        hits = []
        for idx, target in remaining.items():
            if target.verify(candidate):
                hits.append(idx)
                matches.append((target, candidate))
        for idx in hits:
            remaining.pop(idx, None)

        if status_every and tested % status_every == 0:
            print(f"[status] tested {tested:,} candidates; remaining {len(remaining)}")

        if max_candidates and tested >= max_candidates:
            break
        if not keep_going and not remaining:
            break

    return matches, tested, len(remaining)


def main() -> None:
    args = parse_args()
    try:
        targets = load_hashes(
            inline_hashes=args.hashes,
            hash_files=args.hash_files,
            default_algorithm=args.algorithm,
            salt_position=args.salt_position,
        )
    except ValueError as exc:
        raise SystemExit(str(exc))

    charsets = build_charsets(args)
    try:
        candidates = candidate_stream(args, charsets)
    except ValueError as exc:
        raise SystemExit(str(exc))

    try:
        matches, tested, remaining = crack(
            targets,
            candidates,
            status_every=args.status_every,
            max_candidates=args.max_candidates,
            keep_going=args.keep_going,
        )
    except KeyboardInterrupt:
        print("\n[interrupt] stopping early...")
        return

    if matches:
        print("\n[+] recovered credentials:")
        for target, candidate in matches:
            print(f"  {format_match(target, candidate)}")
    else:
        print("\n[!] no matches found.")

    print(f"[summary] tested {tested:,} candidates; cracked {len(matches)}/{len(targets)}; remaining {remaining}")


if __name__ == "__main__":
    main()
