# enigma
A hashcat-like CLI for cracking common password hashes in 2025.

## Highlights
- Algorithms: md5, sha1, sha2/sha3, blake2, pbkdf2 (sha256/sha512), scrypt, plus bcrypt* and Argon2* when the optional packages are installed.
- Attacks: dictionary with mutation tiers, hybrid append-mask, pure mask exhaust, or streaming candidates from stdin.
- Mask tokens: `?l` lower, `?u` upper, `?d` digit, `?s` symbol, `?a` all (charsets overridden with `--charset-*` flags).
- Formats: colon-separated digests or modular strings (argon2/bcrypt/pbkdf2/scrypt), with length-based guessing for bare digests.
- Feedback: progress heartbeat, stop-on-success or keep-going, and a max-candidate guardrail for large masks.

## Quick start
- Dictionary attack: `python3 hashcat.py --hash sha256:5e884... --wordlist rockyou.txt`
- Hybrid digits: `python3 hashcat.py --hash-file hashes.txt --wordlist rockyou.txt --append-mask '?d?d' --mutate aggressive`
- Pure mask (PIN sweep): `python3 hashcat.py --hash-file pins.txt --mask '?d?d?d?d' --algorithm sha1`
- PBKDF2 example: `python3 hashcat.py --hash 'pbkdf2-sha256:600000:salt:HEX_DIGEST' --wordlist words.txt`
- Argon2 example: `python3 hashcat.py --hash '$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$BASE64_DIGEST' --wordlist words.txt`

## Hash format reference
- Simple digests: `algo:digest` or `algo:salt:digest` (salt prepended by default, flip with `--salt-position suffix`). Accepts md5/sha1/sha2/sha3/blake2 in hex or base64. Bare digests need `--algorithm` or will be guessed by length.
- PBKDF2: `pbkdf2-<algo>:iterations:salt:digest` or `$pbkdf2-<algo>$iterations$salt$digest`, where `<algo>` is `sha256` or `sha512`.
- Scrypt: `scrypt:N:r:p:salt:digest` or `$scrypt$ln$r$p$salt$hash` (`ln` is log2(N)).
- Bcrypt: standard `$2b$...` / `$2a$...` strings (requires `bcrypt`).
- Argon2: `$argon2id$...`, `$argon2i$...`, or `$argon2d$...` (requires `argon2-cffi`).

## Mutation and masks
- Mutation levels: `none` (verbatim), `simple` (case flips plus common suffixes/digits), `aggressive` adds light leetspeak with suffixes and digits.
- Mask tokens: `?l` lower, `?u` upper, `?d` digits, `?s` symbols, `?a` all; override sets with `--charset-lower`, `--charset-upper`, `--charset-digit`, `--charset-symbol`.
- Hybrid use: `--append-mask` appends a mask to each dictionary candidate; `--mask` runs a pure mask attack; `--stdin` ingests newline-separated candidates from standard input.

## Operational tips
- `--status-every 0` silences heartbeats; `--max-candidates` caps runaway mask jobs; `--keep-going` hunts collisions after every target is cracked.
- Optional dependencies: `pip install bcrypt argon2-cffi` unlocks bcrypt and Argon2 verification.
- Progress counts are post-mutation; switch to `--mutate none` for curated wordlists or when comparing throughput.

## Sample hashes (password: `password123`)
- Hash set: `python/hashcat_like/example_hashes.txt` (covers sha256, PBKDF2, scrypt, bcrypt, argon2id).
- Minimal wordlist: `python/hashcat_like/example_wordlist.txt`.
- Try it: `python3 hashcat.py --hash-file python/hashcat_like/example_hashes.txt --wordlist python/hashcat_like/example_wordlist.txt --status-every 0 --keep-going`.
