from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

# Optional dependencies - handle gracefully
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    bcrypt = None
    BCRYPT_AVAILABLE = False

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerificationError
    ARGON2_AVAILABLE = True
except ImportError:
    PasswordHasher = None
    VerificationError = None
    ARGON2_AVAILABLE = False


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
    """Decode a hash value from hex or base64."""
    if len(value) % 2 == 0:
        try:
            return binascii.unhexlify(value)
        except binascii.Error:
            pass
    try:
        return base64.b64decode(value)
    except binascii.Error:
        pass
    return value.encode("utf8")


@dataclass
class HashTarget:
    """Represents a hash target for cracking."""
    raw: str
    algorithm: str
    
    def verify(self, candidate: str) -> bool:
        """Verify if candidate matches this hash."""
        raise NotImplementedError("Subclasses must implement verify")


@dataclass
class SimpleHashTarget(HashTarget):
    """Simple hash target (md5, sha1, sha256, etc.)."""
    digest: bytes
    salt: Optional[bytes] = None
    salt_position: str = "prefix"
    
    def verify(self, candidate: str) -> bool:
        if self.algorithm in HASHLIB_ALIASES:
            hash_func = getattr(hashlib, HASHLIB_ALIASES[self.algorithm])
            
            if self.salt:
                if self.salt_position == "prefix":
                    data = self.salt + candidate.encode("utf8")
                else:
                    data = candidate.encode("utf8") + self.salt
            else:
                data = candidate.encode("utf8")
            
            return hash_func(data).digest() == self.digest
        return False


@dataclass
class PBKDF2Target(HashTarget):
    """PBKDF2 hash target."""
    inner_algo: str
    iterations: int
    salt: bytes
    digest: bytes
    
    def verify(self, candidate: str) -> bool:
        import hashlib
        
        if self.inner_algo in HASHLIB_ALIASES:
            hash_module = getattr(hashlib, HASHLIB_ALIASES[self.inner_algo])
            
            # Use hashlib's pbkdf2_hmac
            computed = hashlib.pbkdf2_hmac(
                HASHLIB_ALIASES[self.inner_algo],
                candidate.encode("utf8"),
                self.salt,
                self.iterations,
                len(self.digest)
            )
            return computed == self.digest
        return False


@dataclass
class ScryptTarget(HashTarget):
    """Scrypt hash target."""
    n: int
    r: int
    p: int
    salt: bytes
    digest: bytes
    
    def verify(self, candidate: str) -> bool:
        try:
            import hashlib
            computed = hashlib.scrypt(
                candidate.encode("utf8"),
                salt=self.salt,
                n=self.n,
                r=self.r,
                p=self.p,
                dklen=len(self.digest)
            )
            return computed == self.digest
        except ImportError:
            return False


@dataclass
class BcryptTarget(HashTarget):
    """Bcrypt hash target."""
    hash_string: str
    
    def verify(self, candidate: str) -> bool:
        if not BCRYPT_AVAILABLE:
            return False  # Silently fail if bcrypt not available
        
        try:
            # bcrypt.checkpw expects bytes
            return bcrypt.checkpw(candidate.encode('utf-8'), self.hash_string.encode('utf-8'))
        except Exception:
            return False


@dataclass
class Argon2Target(HashTarget):
    """Argon2 hash target."""
    hash_string: str
    
    def verify(self, candidate: str) -> bool:
        if not ARGON2_AVAILABLE:
            return False  # Silently fail if argon2 not available
        
        try:
            ph = PasswordHasher()
            return ph.verify(self.hash_string, candidate)
        except VerificationError:
            return False
        except Exception:
            return False


def parse_hash_line(text: str, default_algorithm: Optional[str] = None, salt_position: str = "prefix") -> HashTarget:
    """Parse a hash line into a HashTarget."""
    text = text.strip()
    
    # Handle bcrypt format ($2b$...)
    if text.startswith("$2"):
        if not BCRYPT_AVAILABLE:
            # Instead of failing, create a target that will silently fail verification
            return BcryptTarget(raw=text, algorithm="bcrypt", hash_string=text)
        return BcryptTarget(raw=text, algorithm="bcrypt", hash_string=text)
    
    # Handle Argon2 format ($argon2...)
    if text.startswith("$argon2"):
        if not ARGON2_AVAILABLE:
            # Instead of failing, create a target that will silently fail verification
            return Argon2Target(raw=text, algorithm="argon2", hash_string=text)
        return Argon2Target(raw=text, algorithm="argon2", hash_string=text)
    
    # Handle modular PBKDF2 format ($pbkdf2-...)
    if text.startswith("$pbkdf2-"):
        parts = text[1:].split("$")
        if len(parts) >= 4:
            algo_parts = parts[0].split("-")
            if len(algo_parts) == 2:
                inner_algo = algo_parts[1]
                iterations = int(parts[1])
                salt = base64.b64decode(parts[2] + "==")  # Add padding
                digest = base64.b64decode(parts[3] + "==")
                return PBKDF2Target(
                    raw=text,
                    algorithm="pbkdf2",
                    inner_algo=inner_algo,
                    iterations=iterations,
                    salt=salt,
                    digest=digest
                )
    
    # Handle modular scrypt format ($scrypt$...)
    if text.startswith("$scrypt$"):
        parts = text[1:].split("$")
        if len(parts) >= 5:
            n = int(parts[1])  # log2(N)
            r = int(parts[2])
            p = int(parts[3])
            salt = base64.b64decode(parts[4] + "==")
            digest = base64.b64decode(parts[5] + "==")
            return ScryptTarget(
                raw=text,
                algorithm="scrypt",
                n=2**n,  # Convert back from log2
                r=r,
                p=p,
                salt=salt,
                digest=digest
            )
    
    # Split by colon for other formats
    fields = text.split(":")
    
    # Handle PBKDF2: pbkdf2-<algo>:iterations:salt:digest
    if fields[0].startswith("pbkdf2-") and len(fields) == 4:
        algo_parts = fields[0].split("-")
        if len(algo_parts) == 2:
            inner_algo = algo_parts[1]
            iterations = int(fields[1])
            salt = fields[2].encode("utf8")
            digest = decode_hash_value(fields[3])
            return PBKDF2Target(
                raw=text,
                algorithm="pbkdf2",
                inner_algo=inner_algo,
                iterations=iterations,
                salt=salt,
                digest=digest
            )
    
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
    
    # If we get here and have a default algorithm, try to parse as simple hash
    if default_algorithm:
        try:
            algo = normalize_algo(default_algorithm)
            if algo not in {"scrypt", "bcrypt", "argon2", "argon2id", "argon2i", "argon2d"}:
                digest = decode_hash_value(text)
                return SimpleHashTarget(raw=text, algorithm=algo, digest=digest, salt=None)
        except (ValueError, binascii.Error):
            pass
    
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