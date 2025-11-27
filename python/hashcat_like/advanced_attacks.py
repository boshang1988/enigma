"""
Advanced attack modes for Enigma Hashcat

Features:
- Combinator attacks
- Rule-based mutations
- PRINCE attacks
- Markov chain attacks
- Custom word mangling
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple


class RuleEngine:
    """Hashcat-style rule engine for advanced word mangling."""
    
    def __init__(self):
        self.rules: Dict[str, List[str]] = {}
        self.load_builtin_rules()
    
    def load_builtin_rules(self) -> None:
        """Load built-in rule sets."""
        # Basic rules
        self.rules["basic"] = [
            "l",  # Lowercase
            "u",  # Uppercase
            "c",  # Capitalize
            "C",  # Capitalize rest lowercase
            "t",  # Toggle case
            "r",  # Reverse
            "$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$0",  # Append digits
            "^1", "^2", "^3", "^4", "^5", "^6", "^7", "^8", "^9", "^0",  # Prepend digits
            "$!", "$@", "$#", "$$", "$%", "$^", "$&", "$*",  # Append symbols
            "^!", "^@", "^#", "^$", "^%", "^^", "^&", "^*",  # Prepend symbols
            "saa", "see", "sii", "soo", "suu",  # Substitution
            "o65", "o97", "o48",  # Insert character
        ]
        
        # Advanced rules
        self.rules["advanced"] = self.rules["basic"] + [
            "{ ", "} ", "[ ", "] ", "D1", "D2", "D3", "D4", "D5",  # Duplicate/delete
            "x04", "x08", "x16", "x32", "x64",  # Memory rules
            "O65", "O97", "O48",  # Overwrite character
            "i0a", "i0b", "i0c", "i0d", "i0e", "i0f",  # Insert at position
            "o0a", "o0b", "o0c", "o0d", "o0e", "o0f",  # Overwrite at position
            "'1", "'2", "'3", "'4", "'5", "'6", "'7", "'8", "'9", "'0",  # Bitwise shift
            "z2", "z3", "z4", "z5", "z6", "z7", "z8", "z9", "z0",  # Duplicate first N
            "Z2", "Z3", "Z4", "Z5", "Z6", "Z7", "Z8", "Z9", "Z0",  # Duplicate last N
        ]
        
        # Leetspeak rules
        self.rules["leetspeak"] = [
            "sa4", "se3", "si1", "so0", "st7",  # Common leetspeak
            "sA4", "sE3", "sI1", "sO0", "sT7",
            "sa@", "se3", "si1", "so0", "st7",
            "sA@", "sE3", "sI1", "sO0", "sT7",
        ]
    
    def apply_rule(self, word: str, rule: str) -> str:
        """Apply a single rule to a word."""
        if not word:
            return word
        
        # Lowercase
        if rule == "l":
            return word.lower()
        
        # Uppercase
        if rule == "u":
            return word.upper()
        
        # Capitalize
        if rule == "c":
            return word.capitalize()
        
        # Capitalize rest lowercase
        if rule == "C":
            return word[0].upper() + word[1:].lower() if word else word
        
        # Toggle case
        if rule == "t":
            return word.swapcase()
        
        # Reverse
        if rule == "r":
            return word[::-1]
        
        # Append digit
        if rule.startswith("$") and len(rule) == 2 and rule[1] in "0123456789":
            return word + rule[1]
        
        # Prepend digit
        if rule.startswith("^") and len(rule) == 2 and rule[1] in "0123456789":
            return rule[1] + word
        
        # Append symbol
        if rule.startswith("$") and len(rule) == 2 and rule[1] in "!@#$%^&*":
            return word + rule[1]
        
        # Prepend symbol
        if rule.startswith("^") and len(rule) == 2 and rule[1] in "!@#$%^&*":
            return rule[1] + word
        
        # Character substitution
        if rule.startswith("s") and len(rule) == 3:
            old_char = rule[1]
            new_char = rule[2]
            return word.replace(old_char, new_char)
        
        # Insert character
        if rule.startswith("o") and len(rule) == 3:
            char_code = int(rule[1:], 16)
            return word + chr(char_code)
        
        # Duplicate first N characters
        if rule.startswith("z") and len(rule) == 2 and rule[1] in "234567890":
            n = int(rule[1])
            return word[:n] + word
        
        # Duplicate last N characters
        if rule.startswith("Z") and len(rule) == 2 and rule[1] in "234567890":
            n = int(rule[1])
            return word + word[-n:]
        
        # Delete first character
        if rule == "D1":
            return word[1:] if len(word) > 1 else word
        
        # Delete last character
        if rule == "D2":
            return word[:-1] if len(word) > 1 else word
        
        # Delete all but first character
        if rule == "D3":
            return word[0] if word else word
        
        # Delete all but last character
        if rule == "D4":
            return word[-1] if word else word
        
        # Delete all but first and last
        if rule == "D5":
            return word[0] + word[-1] if len(word) > 1 else word
        
        return word
    
    def apply_rule_set(self, word: str, rule_set: str) -> Iterator[str]:
        """Apply a set of rules to a word."""
        if rule_set not in self.rules:
            return
        
        for rule in self.rules[rule_set]:
            result = self.apply_rule(word, rule)
            if result != word:
                yield result


def combinator_attack(
    wordlist_paths: List[str],
    second_wordlist_paths: Optional[List[str]] = None,
    mutate_mode: str = "none",
) -> Iterator[str]:
    """Combinator attack - combine words from two wordlists."""
    from .attacks import wordlist_candidates
    
    # Get first wordlist
    words1 = list(wordlist_candidates(wordlist_paths, mutate_mode=mutate_mode))
    
    # Get second wordlist (or use same if not provided)
    if second_wordlist_paths:
        words2 = list(wordlist_candidates(second_wordlist_paths, mutate_mode=mutate_mode))
    else:
        words2 = words1
    
    # Generate combinations
    for word1 in words1:
        for word2 in words2:
            if word1 != word2:  # Avoid self-combinations
                yield word1 + word2
                yield word1 + " " + word2
                yield word1 + "_" + word2
                yield word1 + "-" + word2
                yield word1 + "." + word2


def prince_attack(
    wordlist_paths: List[str],
    max_length: int = 8,
    mutate_mode: str = "simple",
) -> Iterator[str]:
    """PRINCE attack - generate password candidates using PRINCE algorithm."""
    from .attacks import wordlist_candidates
    
    words = list(wordlist_candidates(wordlist_paths, mutate_mode=mutate_mode))
    
    # Generate PRINCE-like combinations
    for word1 in words:
        for word2 in words:
            if word1 != word2:
                combined = word1 + word2
                if len(combined) <= max_length:
                    yield combined
                    
                    # Also try with common separators
                    for sep in ["", " ", "_", "-", ".", "@", "#", "$"]:
                        candidate = word1 + sep + word2
                        if len(candidate) <= max_length:
                            yield candidate


class MarkovModel:
    """Markov chain model for password generation."""
    
    def __init__(self, order: int = 2):
        self.order = order
        self.model: Dict[str, Dict[str, float]] = {}
    
    def train(self, passwords: List[str]) -> None:
        """Train the Markov model on a list of passwords."""
        for password in passwords:
            # Add start and end markers
            padded = "^" * self.order + password + "$"
            
            for i in range(len(padded) - self.order):
                state = padded[i:i + self.order]
                next_char = padded[i + self.order]
                
                if state not in self.model:
                    self.model[state] = {}
                
                self.model[state][next_char] = self.model[state].get(next_char, 0) + 1
        
        # Normalize probabilities
        for state in self.model:
            total = sum(self.model[state].values())
            for char in self.model[state]:
                self.model[state][char] /= total
    
    def generate(self, count: int = 1000, max_length: int = 12) -> Iterator[str]:
        """Generate passwords using the Markov model."""
        import random
        
        for _ in range(count):
            state = "^" * self.order
            password = ""
            
            while len(password) < max_length:
                if state not in self.model:
                    break
                
                # Choose next character based on probabilities
                chars, weights = zip(*self.model[state].items())
                next_char = random.choices(chars, weights=weights)[0]
                
                if next_char == "$":
                    break
                
                password += next_char
                state = state[1:] + next_char
            
            if password:
                yield password


def markov_attack(
    wordlist_paths: List[str],
    order: int = 2,
    count: int = 1000,
    max_length: int = 12,
) -> Iterator[str]:
    """Markov chain attack - generate passwords using Markov model."""
    from .attacks import wordlist_candidates
    
    # Train model on wordlist
    passwords = list(wordlist_candidates(wordlist_paths, mutate_mode="none"))
    model = MarkovModel(order=order)
    model.train(passwords)
    
    # Generate candidates
    yield from model.generate(count=count, max_length=max_length)


def rule_based_attack(
    wordlist_paths: List[str],
    rule_set: str = "basic",
    mutate_mode: str = "simple",
) -> Iterator[str]:
    """Rule-based attack using the rule engine."""
    from .attacks import wordlist_candidates
    
    rule_engine = RuleEngine()
    
    for word in wordlist_candidates(wordlist_paths, mutate_mode=mutate_mode):
        yield word
        yield from rule_engine.apply_rule_set(word, rule_set)