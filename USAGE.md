# Enigma Hashcat - Usage Guide

A comprehensive guide to using the enhanced Enigma Hashcat toolkit with modern features for 2025.

## Quick Start

### Basic Dictionary Attack
```bash
python3 hashcat.py --hash sha256:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f --wordlist rockyou.txt
```

### Multiple Hashes from File
```bash
python3 hashcat.py --hash-file hashes.txt --wordlist common_passwords.txt
```

### Mask Attack (4-digit PIN)
```bash
python3 hashcat.py --hash-file pins.txt --mask '?d?d?d?d' --algorithm sha1
```

## Advanced Attack Modes

### Combinator Attack
Combine words from two different wordlists:
```bash
python3 hashcat.py --hash-file hashes.txt --combinator words1.txt words2.txt
```

### Rule-Based Attack
Apply hashcat-style rules to wordlists:
```bash
# Built-in rule sets
python3 hashcat.py --hash-file hashes.txt --wordlist base_words.txt --rule advanced

# Custom rule file
python3 hashcat.py --hash-file hashes.txt --wordlist base_words.txt --rule-file myrules.rule
```

### PRINCE Attack
Generate password candidates using probability chains:
```bash
python3 hashcat.py --hash-file hashes.txt --prince --wordlist fragments.txt
```

### Markov Chain Attack
Generate passwords using Markov models:
```bash
python3 hashcat.py --hash-file hashes.txt --markov 10000 --wordlist training_set.txt
```

### Hybrid Attack
Append masks to dictionary words:
```bash
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --append-mask '?d?d?d'
```

## Performance Optimization

### Multi-threading
Use multiple CPU cores for faster cracking:
```bash
python3 hashcat.py --hash-file hashes.txt --wordlist large_wordlist.txt --threads 8
```

### Batch Processing
Adjust batch size for memory efficiency:
```bash
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --batch-size 50000
```

## Session Management

### Save Session
Save progress to resume later:
```bash
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --session my_attack
```

### Restore Session
Resume from saved session:
```bash
python3 hashcat.py --restore my_attack.json
```

### List Sessions
View all saved sessions:
```bash
python3 hashcat.py --list-sessions
```

### Export Results
Export cracked passwords in various formats:
```bash
# JSON format
python3 hashcat.py --restore my_attack.json --export json > results.json

# CSV format
python3 hashcat.py --restore my_attack.json --export csv > results.csv

# Hashcat potfile format
python3 hashcat.py --restore my_attack.json --export hashcat > potfile.txt
```

## Benchmarking and System Info

### Performance Benchmark
Test system performance with all algorithms:
```bash
python3 hashcat.py --benchmark
```

### System Information
Display hardware capabilities:
```bash
python3 hashcat.py --system-info
```

## Advanced Configuration

### Custom Character Sets
Define custom character sets for mask attacks:
```bash
# Custom symbol set
python3 hashcat.py --hash-file hashes.txt --mask '?u?l?l?s' --charset-symbol '!@#$%'

# Custom digit set
python3 hashcat.py --hash-file hashes.txt --mask '?d?d?d' --charset-digit '13579'
```

### Mutation Levels
Control word mutation intensity:
```bash
# No mutation (verbatim)
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --mutate none

# Simple mutation (case changes + common suffixes)
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --mutate simple

# Aggressive mutation (leet speak + extensive suffixes)
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --mutate aggressive
```

### Operational Controls
Fine-tune cracking behavior:
```bash
# Disable status updates
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --status-every 0

# Set candidate limit
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --max-candidates 1000000

# Continue after finding matches (useful for collisions)
python3 hashcat.py --hash-file hashes.txt --wordlist words.txt --keep-going
```

## Hash Format Reference

### Simple Hashes
```
sha256:ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
md5:5d41402abc4b2a76b9719d911017c592
sha1:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```

### Salted Hashes
```
sha256:salt:digest
sha256:digest:salt  # with --salt-position suffix
```

### PBKDF2
```
pbkdf2-sha256:120000:salt:digest
$pbkdf2-sha256$120000$salt$digest
```

### Scrypt
```
scrypt:16384:8:1:salt:digest
$scrypt$14$8$1$salt$digest  # ln = log2(N)
```

### Bcrypt
```
$2b$12$saltdigest
```

### Argon2
```
$argon2id$v=19$m=65536,t=3,p=2$salt$digest
```

## Mask Token Reference

- `?l` - Lowercase letters (abcdefghijklmnopqrstuvwxyz)
- `?u` - Uppercase letters (ABCDEFGHIJKLMNOPQRSTUVWXYZ)
- `?d` - Digits (0123456789)
- `?s` - Symbols (!@#$%^&*()-_=+[]{};:'",.<>/?\|`~)
- `?a` - All characters (lower + upper + digits + symbols)
- `?h` - Hexadecimal digits (0123456789abcdef)

## Built-in Rule Sets

### Basic Rules
- Case transformations (l, u, c, C, t)
- Reverse (r)
- Append/prepend digits ($1, ^1, etc.)
- Append/prepend symbols ($!, ^!, etc.)
- Character substitution (sa4, se3, etc.)

### Advanced Rules
- All basic rules
- Duplicate/delete operations ({, }, D1, etc.)
- Memory rules (x04, x08, etc.)
- Overstrike operations (O65, O97, etc.)
- Shift operations ('6, '7, etc.)
- Purge operations (@a, @e, etc.)

### Leet Rules
- Character substitutions for leet speak
- sa4, se3, si1, so0, ss5, st7, sl1
- Capital letter equivalents

## Performance Tips

1. **Use appropriate mutation levels**: Start with `simple` and move to `aggressive` if needed
2. **Leverage parallel processing**: Use `--threads` to utilize all CPU cores
3. **Optimize batch size**: Larger batches for fast hashes, smaller for slow ones
4. **Use session management**: Save progress for long-running attacks
5. **Benchmark first**: Use `--benchmark` to identify fastest algorithms
6. **Combine attack modes**: Use rules + masks for comprehensive coverage

## Troubleshooting

### Common Issues

**"No hashes provided"**
- Check hash file path and format
- Ensure hashes are not commented out with #

**"Unknown algorithm"**
- Verify algorithm name spelling
- Check if optional dependencies are installed (bcrypt, argon2-cffi)

**"Memory error"**
- Reduce batch size with `--batch-size`
- Use smaller wordlists or split large files

**"Slow performance"**
- Run benchmark to identify bottlenecks
- Check system resources (CPU, memory)
- Consider using faster algorithms when possible

### Getting Help

- Check hash formats in the examples
- Run with `--system-info` to verify hardware detection
- Use `--benchmark` to test algorithm performance
- Review session files for progress tracking

## Examples Directory

See `python/hashcat_like/` for example files:
- `example_hashes.txt` - Sample hashes for testing
- `example_wordlist.txt` - Minimal wordlist for examples