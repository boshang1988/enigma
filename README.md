# So I really don't want to look at that piece of shit Twitch (quality > quantity always), however I thought about explaining how erosolar secured credentials and how to obtain them from Twitch and how to commit crimes with them, OR explain why not; this is the key you must do it

<img width="674" height="1014" alt="image" src="https://github.com/user-attachments/assets/955e78eb-3199-44f4-9c1f-8de9ecbafe51" />


# Enigma Hashcat
A modern hashcat-like CLI for cracking common password hashes in 2025.

## Highlights
- **Algorithms**: md5, sha1, sha2/sha3, blake2, pbkdf2 (sha256/sha512), scrypt, plus bcrypt* and Argon2* when the optional packages are installed.
- **Attacks**: dictionary with mutation tiers, hybrid append-mask, pure mask exhaust, combinator, rule-based, PRINCE, Markov chain, or streaming candidates from stdin.
- **Mask tokens**: `?l` lower, `?u` upper, `?d` digit, `?s` symbol, `?a` all (charsets overridden with `--charset-*` flags).
- **Formats**: colon-separated digests or modular strings (argon2/bcrypt/pbkdf2/scrypt), with length-based guessing for bare digests.
- **Feedback**: progress heartbeat, stop-on-success or keep-going, and a max-candidate guardrail for large masks.
- **Session Management**: Save/restore cracking sessions, resume interrupted attacks, export results in multiple formats.
- **Performance**: Multi-threading, GPU acceleration detection, memory-efficient processing.
- **Benchmarking**: Comprehensive algorithm performance testing and system capability assessment.

## Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/enigma.git
cd enigma

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
```bash
# Dictionary attack
python3 hashcat.py --attack-mode dictionary --wordlist rockyou.txt --hash sha256:5e884...

# Mask attack (PIN cracking)
python3 hashcat.py --attack-mode mask --mask ?d?d?d?d --hash-file pins.txt

# Hybrid attack (dictionary + mask)
python3 hashcat.py --attack-mode hybrid --wordlist words.txt --append-mask ?d?d

# Combinator attack
python3 hashcat.py --attack-mode combinator --wordlist words1.txt --second-wordlist words2.txt

# Rule-based attack
python3 hashcat.py --attack-mode rule --wordlist words.txt --rule-set advanced

# PRINCE attack
python3 hashcat.py --attack-mode prince --wordlist words.txt --max-length 8

# Markov attack
python3 hashcat.py --attack-mode markov --wordlist words.txt --markov-order 2 --markov-count 1000
```

## Advanced Features

### Session Management
```bash
# Save session for later restoration
python3 hashcat.py --save-session my_session --attack-mode dictionary --wordlist words.txt

# Restore session and continue
python3 hashcat.py --restore my_session

# List all saved sessions
python3 hashcat.py --list-sessions

# Delete a session
python3 hashcat.py --delete-session my_session

# Export session results
python3 hashcat.py --export-session results.json --export-format json
```

### Performance Optimization
```bash
# Use multiple threads
python3 hashcat.py --parallel 8 --attack-mode dictionary --wordlist words.txt

# Disable status updates for maximum speed
python3 hashcat.py --status-every 0 --attack-mode mask --mask ?d?d?d?d

# Set candidate limit for large attacks
python3 hashcat.py --max-candidates 1000000 --attack-mode hybrid --wordlist words.txt --append-mask ?d?d?d
```

### System Information and Benchmarking
```bash
# Show system capabilities
python3 hashcat.py --system-info

# Run comprehensive benchmarks
python3 hashcat.py --benchmark
```

## Attack Modes

### 1. Dictionary Attack
Basic wordlist-based attack with optional mutation.
```bash
python3 hashcat.py --attack-mode dictionary --wordlist rockyou.txt --hash sha256:5e884...
```

### 2. Mask Attack
Pure mask-based attack for brute-force scenarios.
```bash
python3 hashcat.py --attack-mode mask --mask ?u?l?l?l?d?d?d --hash-file hashes.txt
```

### 3. Hybrid Attack
Combine dictionary words with mask patterns.
```bash
python3 hashcat.py --attack-mode hybrid --wordlist words.txt --append-mask ?d?d
```

### 4. Combinator Attack
Combine words from two different wordlists.
```bash
python3 hashcat.py --attack-mode combinator --wordlist words1.txt --second-wordlist words2.txt
```

### 5. Rule-Based Attack
Apply hashcat-style rules to dictionary words.
```bash
python3 hashcat.py --attack-mode rule --wordlist words.txt --rule-set advanced
```

### 6. PRINCE Attack
Generate password candidates using PRINCE algorithm.
```bash
python3 hashcat.py --attack-mode prince --wordlist words.txt --max-length 8
```

### 7. Markov Chain Attack
Generate passwords using Markov model trained on wordlist.
```bash
python3 hashcat.py --attack-mode markov --wordlist words.txt --markov-order 2 --markov-count 1000
```

### 8. Standard Input
Stream candidates from stdin or other tools.
```bash
echo "password123" | python3 hashcat.py --attack-mode stdin --hash sha256:5e884...
```

## Hash Format Reference

### Simple Digests
- `algo:digest` or `algo:salt:digest` (salt prepended by default, flip with `--salt-position suffix`)
- Accepts md5/sha1/sha2/sha3/blake2 in hex or base64
- Bare digests need `--algorithm` or will be guessed by length

### PBKDF2
- `pbkdf2-<algo>:iterations:salt:digest` or `$pbkdf2-<algo>$iterations$salt$digest`
- Where `<algo>` is `sha256` or `sha512`

### Scrypt
- `scrypt:N:r:p:salt:digest` or `$scrypt$ln$r$p$salt$hash` (`ln` is log2(N))

### Bcrypt
- Standard `$2b$...` / `$2a$...` strings (requires `bcrypt`)

### Argon2
- `$argon2id$...`, `$argon2i$...`, or `$argon2d$...` (requires `argon2-cffi`)

## Mutation and Masks

### Mutation Levels
- `none`: Use wordlist words verbatim
- `simple`: Case flips plus common suffixes/digits
- `aggressive`: Adds light leetspeak with suffixes and digits

### Mask Tokens
- `?l`: Lowercase letters (abcdefghijklmnopqrstuvwxyz)
- `?u`: Uppercase letters (ABCDEFGHIJKLMNOPQRSTUVWXYZ)
- `?d`: Digits (0123456789)
- `?s`: Symbols (!@#$%^&*()_+-=[]{}|;:,.<>?)
- `?a`: All characters (lower + upper + digits + symbols)

### Custom Character Sets
```bash
python3 hashcat.py --charset-lower "abc" --charset-digit "123" --mask ?l?l?d
```

## Rule-Based Attacks

### Built-in Rule Sets
- `basic`: Lowercase, uppercase, capitalize, append/prepend digits/symbols
- `advanced`: Advanced rules including leetspeak, character substitution, duplication
- `leetspeak`: Common leetspeak substitutions (a->4, e->3, etc.)

### Example Rules
- `l`: Lowercase the word
- `u`: Uppercase the word
- `c`: Capitalize the word
- `$1`: Append digit 1
- `^!`: Prepend symbol !
- `sa4`: Substitute 'a' with '4'
- `r`: Reverse the word

## Operational Tips

- Use `--status-every 0` to silence heartbeats for maximum speed
- `--max-candidates` caps runaway mask jobs
- `--keep-going` hunts collisions after every target is cracked
- Progress counts are post-mutation; switch to `--mutate none` for curated wordlists
- Optional dependencies: `pip install bcrypt argon2-cffi` unlocks bcrypt and Argon2 verification

## Sample Hashes

### Test Files
- Hash set: `python/hashcat_like/example_hashes.txt` (covers sha256, PBKDF2, scrypt, bcrypt, argon2id)
- Minimal wordlist: `python/hashcat_like/example_wordlist.txt`

### Test Command
```bash
python3 hashcat.py --hash-file python/hashcat_like/example_hashes.txt --wordlist python/hashcat_like/example_wordlist.txt --status-every 0 --keep-going
```

## Performance Optimization

### Multi-threading
```bash
# Use all available CPU cores (minus one for system)
python3 hashcat.py --parallel auto --attack-mode dictionary --wordlist words.txt

# Specify exact number of threads
python3 hashcat.py --parallel 8 --attack-mode mask --mask ?d?d?d?d
```

### Memory Management
- Large wordlists are streamed to avoid memory exhaustion
- Candidate generation is lazy and memory-efficient
- Session files include compression for large result sets

### GPU Acceleration
- Automatic detection of CUDA/OpenCL capable devices
- Falls back to CPU processing if GPU unavailable
- Performance statistics include GPU utilization when available

## Development

### Project Structure
```
enigma/
├── hashcat.py                 # Main entry point
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── python/
    └── hashcat_like/
        ├── main.py            # Unified interface
        ├── enhanced_cli.py    # Enhanced CLI with modern features
        ├── cli.py             # Basic CLI
        ├── core.py            # Hash parsing and verification
        ├── attacks.py         # Basic attack modes
        ├── advanced_attacks.py # Advanced attack modes
        ├── session.py         # Session management
        ├── performance.py     # Performance optimization
        ├── benchmark.py       # Benchmarking suite
        └── example_hashes.txt # Sample test data
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Testing
```bash
# Run basic tests
python3 -m pytest tests/

# Run with example data
python3 hashcat.py --hash-file python/hashcat_like/example_hashes.txt --wordlist python/hashcat_like/example_wordlist.txt
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by Hashcat and John the Ripper
- Built with modern Python best practices
- Designed for security researchers and penetration testers
