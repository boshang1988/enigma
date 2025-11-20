from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

try:
    import bcrypt
except ImportError:  # pragma: no cover - optional dependency
    bcrypt = None

try:
    from argon2 import low_level as argon2_low_level
    from argon2.exceptions import VerificationError
except ImportError:  # pragma: no cover - optional dependency
    argon2_low_level = None
    VerificationError = None


HASHLIB_ALIASES: Dict[str, str] = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha3-256": "sha3_256",
    "sha3-512": "sha3_512",
    "blake2b": "blake2b",
    "blake2s": "blake2s",
}


def normalize_algo(name: str) -> str:
    clean = name.strip().lower().replace("_", "-")
    if clean.startswith("pbkdf2-"):
        inner = clean.replace("pbkdf2-", "", 1)
        if inner not in HASHLIB_ALIASES:
            raise ValueError(f"Unsupported PBKDF2 algorithm: {name}")
        return f"pbkdf2-{inner}"
    if clean in HASHLIB_ALIASES:
        return clean
    if clean in {"scrypt", "bcrypt", "argon2", "argon2id", "argon2i", "argon2d"}:
        return clean
    raise ValueError(f"Unsupported algorithm: {name}")


def decode_hash_value(value: str) -> bytes:
    text = value.strip()
    try:
        return bytes.fromhex(text)
    except (ValueError, binascii.Error):
        pass
    # try url-safe base64 with padding fixups
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return text.encode("utf8")


def guess_digest_algorithm(digest: bytes) -> Optional[str]:
    candidates = {
        16: ["md5"],
        20: ["sha1"],
        28: ["sha224"],
        32: ["sha256", "sha3-256", "blake2s"],
        48: ["sha384"],
        64: ["sha512", "sha3-512", "blake2b"],
    }
    choices = candidates.get(len(digest))
    return choices[0] if choices else None


@dataclass
class HashTarget:
    raw: str
    algorithm: str

    def verify(self, candidate: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def label(self) -> str:
        return f"{self.algorithm}:{self.raw}"


@dataclass
class SimpleHashTarget(HashTarget):
    digest: bytes
    salt: Optional[bytes] = None
    salt_position: str = "prefix"

    def verify(self, candidate: str) -> bool:
        data = candidate.encode("utf8")
        if self.salt:
            data = self.salt + data if self.salt_position == "prefix" else data + self.salt
        digest = hashlib.new(HASHLIB_ALIASES[self.algorithm], data).digest()
        return digest == self.digest


@dataclass
class Pbkdf2Target(HashTarget):
    digest: bytes
    salt: bytes
    iterations: int

    def verify(self, candidate: str) -> bool:
        dklen = len(self.digest)
        derived = hashlib.pbkdf2_hmac(
            HASHLIB_ALIASES[self.algorithm.replace("pbkdf2-", "")],
            candidate.encode("utf8"),
            self.salt,
            self.iterations,
            dklen=dklen,
        )
        return derived == self.digest


@dataclass
class ScryptTarget(HashTarget):
    digest: bytes
    salt: bytes
    n: int
    r: int
    p: int

    def verify(self, candidate: str) -> bool:
        derived = hashlib.scrypt(
            candidate.encode("utf8"),
            salt=self.salt,
            n=self.n,
            r=self.r,
            p=self.p,
            dklen=len(self.digest),
        )
        return derived == self.digest


@dataclass
class BcryptTarget(HashTarget):
    encoded: bytes

    def verify(self, candidate: str) -> bool:
        if bcrypt is None:
            raise RuntimeError("Install bcrypt to verify bcrypt hashes.")
        return bcrypt.checkpw(candidate.encode("utf8"), self.encoded)


@dataclass
class Argon2Target(HashTarget):
    encoded: str
    argon_type: str

    def verify(self, candidate: str) -> bool:
        if argon2_low_level is None or VerificationError is None:
            raise RuntimeError("Install argon2-cffi to verify Argon2 hashes.")
        try:
            return argon2_low_level.verify_secret(
                self.encoded.encode("utf8"),
                candidate.encode("utf8"),
                type=self.argon_type,
            )
        except VerificationError:
            return False


def parse_hash_line(
    raw_line: str,
    default_algorithm: Optional[str] = None,
    salt_position: str = "prefix",
) -> HashTarget:
    if salt_position not in {"prefix", "suffix"}:
        raise ValueError("salt_position must be 'prefix' or 'suffix'")
    text = raw_line.strip()
    if not text or text.startswith("#"):
        raise ValueError("empty hash line")

    if text.startswith("$argon2"):
        if argon2_low_level is None:
            raise RuntimeError("argon2-cffi is required to crack Argon2 entries.")
        if "$" not in text:
            raise ValueError(f"Invalid Argon2 line: {text}")
        if text.startswith("$argon2id$"):
            argon_type = argon2_low_level.Type.ID
        elif text.startswith("$argon2i$"):
            argon_type = argon2_low_level.Type.I
        else:
            argon_type = argon2_low_level.Type.D
        algo_label = "argon2id" if argon_type is argon2_low_level.Type.ID else ("argon2i" if argon_type is argon2_low_level.Type.I else "argon2d")
        return Argon2Target(raw=text, algorithm=algo_label, encoded=text, argon_type=argon_type)

    if text.startswith("$2"):
        if bcrypt is None:
            raise RuntimeError("bcrypt is required to crack bcrypt entries.")
        return BcryptTarget(raw=text, algorithm="bcrypt", encoded=text.encode("utf8"))

    # Passlib-style PBKDF2: $pbkdf2-sha256$29000$salt$hash
    if text.startswith("$pbkdf2-"):
        parts = [p for p in text.split("$") if p]
        if len(parts) != 4:
            raise ValueError(f"Cannot parse PBKDF2 hash: {text}")
        algo = normalize_algo(parts[0])
        iterations = int(parts[1])
        salt = parts[2].encode("utf8")
        digest = decode_hash_value(parts[3])
        return Pbkdf2Target(raw=text, algorithm=algo, digest=digest, salt=salt, iterations=iterations)

    # Passlib-style scrypt: $scrypt$ln$r$p$salt$hash
    if text.startswith("$scrypt$") or text.startswith("scrypt$"):
        parts = [p for p in text.split("$") if p]
        if len(parts) != 6:
            raise ValueError(f"Cannot parse scrypt hash: {text}")
        n = 2 ** int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        salt = parts[4].encode("utf8")
        digest = decode_hash_value(parts[5])
        return ScryptTarget(raw=text, algorithm="scrypt", digest=digest, salt=salt, n=n, r=r, p=p)

    fields = text.split(":")
    if len(fields) == 1:
        digest = decode_hash_value(fields[0])
        algo_name = default_algorithm or guess_digest_algorithm(digest)
        if not algo_name:
            raise ValueError("Provide --algorithm when hashes omit an algorithm prefix.")
        algo = normalize_algo(algo_name)
        if algo.startswith("pbkdf2") or algo in {"scrypt", "bcrypt", "argon2", "argon2id", "argon2i", "argon2d"}:
            raise ValueError("KDFs with salts (PBKDF2/scrypt/argon2/bcrypt) need their full structured format.")
        return SimpleHashTarget(raw=text, algorithm=algo, digest=digest, salt=None, salt_position=salt_position)

    # pbkdf2-sha256:iterations:salt:hash
    if fields[0].lower().startswith("pbkdf2-") and len(fields) == 4:
        algo = normalize_algo(fields[0])
        iterations = int(fields[1])
        salt = fields[2].encode("utf8")
        digest = decode_hash_value(fields[3])
        return Pbkdf2Target(raw=text, algorithm=algo, digest=digest, salt=salt, iterations=iterations)

    # scrypt:N:r:p:salt:hash
    if fields[0].lower() == "scrypt" and len(fields) == 6:
        n = int(fields[1])
        r = int(fields[2])
        p = int(fields[3])
        salt = fields[4].encode("utf8")
        digest = decode_hash_value(fields[5])
        return ScryptTarget(raw=text, algorithm="scrypt", digest=digest, salt=salt, n=n, r=r, p=p)

    if len(fields) in (2, 3):
        algo = normalize_algo(fields[0])
        if algo.startswith("pbkdf2-"):
            raise ValueError("PBKDF2 entries must include iterations and salt.")
        if algo in {"scrypt", "bcrypt", "argon2", "argon2id", "argon2i", "argon2d"}:
            raise ValueError("Use the structured format for scrypt/argon2/bcrypt hashes.")
        digest = decode_hash_value(fields[-1])
        salt = fields[1].encode("utf8") if len(fields) == 3 else None
        return SimpleHashTarget(raw=text, algorithm=algo, digest=digest, salt=salt, salt_position=salt_position)

    raise ValueError(f"Unrecognized hash line: {text}")


def load_hashes(
    inline_hashes: Sequence[str],
    hash_files: Sequence[str],
    default_algorithm: Optional[str],
    salt_position: str = "prefix",
) -> List[HashTarget]:
    lines: List[str] = []
    for inline in inline_hashes:
        lines.append(inline)
    for path in hash_files:
        with open(path, "r", encoding="utf8") as handle:
            lines.extend([ln.strip() for ln in handle if ln.strip() and not ln.lstrip().startswith("#")])

    targets: List[HashTarget] = []
    for line in lines:
        try:
            target = parse_hash_line(line, default_algorithm=default_algorithm, salt_position=salt_position)
        except (ValueError, RuntimeError) as exc:
            raise ValueError(f"Failed to parse hash '{line}': {exc}") from exc
        targets.append(target)
    if not targets:
        raise ValueError("No hashes provided.")
    return targets


def format_match(target: HashTarget, candidate: str) -> str:
    return f"{target.raw} -> {candidate} ({target.algorithm})"
