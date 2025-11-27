"""
Enhanced CLI for Enigma Hashcat with modern features

Features:
- Advanced attack modes
- Session management
- Performance optimization
- Benchmarking
- Rule-based attacks
- Combinator attacks
- PRINCE attacks
- Markov chain attacks
"""

from __future__ import annotations

import argparse
import itertools
import sys
import time
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .advanced_attacks import (
    RuleEngine,
    combinator_attack,
    markov_attack,
    prince_attack,
    rule_based_attack,
)
from .attacks import (
    DEFAULT_CHARSETS,
    append_mask_candidates,
    mask_candidates,
    mutate_word,
    wordlist_candidates,
)
from .benchmark import BenchmarkSuite, system_info
from .core import HashTarget, format_match, load_hashes
from .performance import ParallelProcessor, format_eta
from .session import SessionManager, SessionState


class EnhancedCLI:
    """Enhanced CLI with modern hashcat features."""
    
    def __init__(self):
        self.session_manager = SessionManager()
        self.parallel_processor = ParallelProcessor()
    
    def build_charsets(self, args: argparse.Namespace) -> Dict[str, str]:
        """Build character sets from CLI arguments."""
        charsets = DEFAULT_CHARSETS.copy()
        if args.charset_lower:
            charsets["l"] = args.charset_lower
        if args.charset_upper:
            charsets["u"] = args.charset_upper
        if args.charset_digit:
            charsets["d"] = args.charset_digit
        if args.charset_symbol:
            charsets["s"] = args.charset_symbol
        return charsets
    
    def candidate_stream(self, args: argparse.Namespace, charsets: Dict[str, str]) -> Iterator[str]:
        """Generate candidate passwords based on attack mode."""
        if args.attack_mode == "dictionary":
            return wordlist_candidates(args.wordlists, mutate_mode=args.mutate)
        
        elif args.attack_mode == "mask":
            if not args.masks:
                raise ValueError("Mask attack requires --mask arguments")
            return mask_candidates(args.masks, charsets)
        
        elif args.attack_mode == "hybrid":
            if not args.wordlists:
                raise ValueError("Hybrid attack requires --wordlist arguments")
            if not args.append_mask:
                raise ValueError("Hybrid attack requires --append-mask")
            return append_mask_candidates(args.wordlists, args.append_mask, charsets, mutate_mode=args.mutate)
        
        elif args.attack_mode == "combinator":
            return combinator_attack(args.wordlists, args.second_wordlist, mutate_mode=args.mutate)
        
        elif args.attack_mode == "rule":
            return rule_based_attack(args.wordlists, args.rule_set, mutate_mode=args.mutate)
        
        elif args.attack_mode == "prince":
            return prince_attack(args.wordlists, args.max_length, mutate_mode=args.mutate)
        
        elif args.attack_mode == "markov":
            return markov_attack(args.wordlists, args.markov_order, args.markov_count, args.max_length)
        
        elif args.attack_mode == "stdin":
            return self.stdin_candidates()
        
        else:
            raise ValueError(f"Unknown attack mode: {args.attack_mode}")
    
    def stdin_candidates(self) -> Iterator[str]:
        """Read candidates from stdin."""
        for line in sys.stdin:
            line = line.strip()
            if line:
                yield line
    
    def parse_args(self) -> argparse.Namespace:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description="Enigma Hashcat - Modern password recovery toolkit for 2025",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
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
  
  # Session management
  python3 hashcat.py --save-session my_session --attack-mode dictionary --wordlist words.txt
  python3 hashcat.py --restore my_session
  
  # Benchmarking
  python3 hashcat.py --benchmark
  python3 hashcat.py --system-info
"""
        )
        
        # Hash input
        hash_group = parser.add_argument_group("Hash Input")
        hash_group.add_argument("--hash", action="append", dest="hashes", default=[], 
                              help="Hash entry (can be repeated).")
        hash_group.add_argument("--hash-file", action="append", dest="hash_files", default=[], 
                              help="File containing hashes (one per line, comments with #).")
        hash_group.add_argument("--algorithm", 
                              help="Default algorithm when hashes omit an explicit prefix.")
        hash_group.add_argument("--salt-position", choices=["prefix", "suffix"], default="prefix",
                              help="Position of salt for simple digests.")
        
        # Attack modes
        attack_group = parser.add_argument_group("Attack Modes")
        attack_group.add_argument("--attack-mode", 
                                choices=["dictionary", "mask", "hybrid", "combinator", 
                                        "rule", "prince", "markov", "stdin"],
                                default="dictionary",
                                help="Attack mode to use (default: dictionary)")
        
        # Dictionary attack
        dict_group = parser.add_argument_group("Dictionary Attack")
        dict_group.add_argument("--wordlist", action="append", dest="wordlists", default=[],
                              help="Path to a wordlist for dictionary attacks.")
        dict_group.add_argument("--mutate", choices=["none", "simple", "aggressive"], 
                              default="simple",
                              help="Mutation level for dictionary words.")
        
        # Mask attack
        mask_group = parser.add_argument_group("Mask Attack")
        mask_group.add_argument("--mask", action="append", dest="masks", default=[],
                              help="Mask pattern using Hashcat-style tokens.")
        mask_group.add_argument("--append-mask",
                              help="Hybrid attack: append a mask onto every wordlist candidate.")
        
        # Advanced attacks
        advanced_group = parser.add_argument_group("Advanced Attacks")
        advanced_group.add_argument("--second-wordlist", action="append", dest="second_wordlist", default=[],
                                  help="Second wordlist for combinator attacks.")
        advanced_group.add_argument("--rule-set", choices=["basic", "advanced", "leetspeak"], 
                                  default="basic",
                                  help="Rule set for rule-based attacks.")
        advanced_group.add_argument("--max-length", type=int, default=8,
                                  help="Maximum password length for PRINCE attacks.")
        advanced_group.add_argument("--markov-order", type=int, default=2,
                                  help="Markov model order for Markov attacks.")
        advanced_group.add_argument("--markov-count", type=int, default=1000,
                                  help="Number of passwords to generate with Markov model.")
        
        # Character sets
        charset_group = parser.add_argument_group("Character Sets")
        charset_group.add_argument("--charset-lower", default=DEFAULT_CHARSETS["l"],
                                 help="Custom lowercase character set.")
        charset_group.add_argument("--charset-upper", default=DEFAULT_CHARSETS["u"],
                                 help="Custom uppercase character set.")
        charset_group.add_argument("--charset-digit", default=DEFAULT_CHARSETS["d"],
                                 help="Custom digit character set.")
        charset_group.add_argument("--charset-symbol", default=DEFAULT_CHARSETS["s"],
                                 help="Custom symbol character set.")
        
        # Session management
        session_group = parser.add_argument_group("Session Management")
        session_group.add_argument("--save-session",
                                 help="Save session to file for later restoration.")
        session_group.add_argument("--restore",
                                 help="Restore session from file.")
        session_group.add_argument("--list-sessions", action="store_true",
                                 help="List all saved sessions.")
        session_group.add_argument("--delete-session",
                                 help="Delete a saved session.")
        session_group.add_argument("--export-session",
                                 help="Export session to file in specified format.")
        session_group.add_argument("--export-format", choices=["json", "csv", "hashcat"], 
                                 default="json",
                                 help="Export format for session data.")
        
        # Performance and limits
        perf_group = parser.add_argument_group("Performance & Limits")
        perf_group.add_argument("--status-every", type=int, default=1000,
                              help="Print status every N candidates (0 to disable).")
        perf_group.add_argument("--max-candidates", type=int,
                              help="Maximum number of candidates to test.")
        perf_group.add_argument("--keep-going", action="store_true",
                              help="Continue after finding matches.")
        perf_group.add_argument("--parallel", type=int, default=1,
                              help="Number of parallel workers.")
        
        # System commands
        system_group = parser.add_argument_group("System Commands")
        system_group.add_argument("--benchmark", action="store_true",
                                help="Run performance benchmarks.")
        system_group.add_argument("--system-info", action="store_true",
                                help="Show system information.")
        
        return parser.parse_args()
    
    def handle_benchmark(self) -> None:
        """Handle benchmark command."""
        benchmark = BenchmarkSuite()
        benchmark.run_all()
    
    def handle_system_info(self) -> None:
        """Handle system info command."""
        info = system_info()
        print("System Information:")
        for key, value in info.items():
            print(f"  {key}: {value}")
    
    def handle_list_sessions(self) -> None:
        """Handle list sessions command."""
        sessions = self.session_manager.list_sessions()
        if not sessions:
            print("No saved sessions found.")
            return
        
        print("Saved sessions:")
        for session_id in sessions:
            print(f"  {session_id}")
    
    def crack(self, targets: List[HashTarget], candidates: Iterator[str], 
              args: argparse.Namespace) -> Tuple[List[Tuple[HashTarget, str]], int, List[HashTarget]]:
        """Crack hashes using the provided candidates."""
        matches: List[Tuple[HashTarget, str]] = []
        tested = 0
        remaining = targets.copy()
        
        start_time = time.time()
        last_status = start_time
        
        for candidate in candidates:
            # Check limits
            if args.max_candidates and tested >= args.max_candidates:
                break
            
            # Test candidate against remaining targets
            for target in remaining:
                if target.verify(candidate):
                    matches.append((target, candidate))
                    print(f"[+] {format_match(target, candidate)}")
                    
                    if not args.keep_going:
                        remaining.remove(target)
                        break
            
            tested += 1
            
            # Status updates
            if args.status_every > 0 and tested % args.status_every == 0:
                current_time = time.time()
                elapsed = current_time - start_time
                rate = tested / elapsed if elapsed > 0 else 0
                eta = format_eta(elapsed, tested, len(remaining))
                
                print(f"[status] tested {tested:,} candidates, rate: {rate:.1f}/s, {len(matches)} matches, {len(remaining)} remaining, ETA: {eta}")
                last_status = current_time
            
            # Check if done
            if not args.keep_going and not remaining:
                break
        
        return matches, tested, remaining
    
    def main(self) -> None:
        """Main entry point for enhanced CLI."""
        args = self.parse_args()
        
        # Handle special commands
        if args.benchmark:
            self.handle_benchmark()
            return
        
        if args.system_info:
            self.handle_system_info()
            return
        
        if args.list_sessions:
            self.handle_list_sessions()
            return
        
        if args.delete_session:
            if self.session_manager.delete_session(args.delete_session):
                print(f"Session '{args.delete_session}' deleted.")
            else:
                print(f"Session '{args.delete_session}' not found.")
            return
        
        # Load hashes
        try:
            targets = load_hashes(
                inline_hashes=args.hashes,
                hash_files=args.hash_files,
                default_algorithm=args.algorithm,
                salt_position=args.salt_position,
            )
        except ValueError as exc:
            raise SystemExit(str(exc))
        
        # Restore session if requested
        session: Optional[SessionState] = None
        if args.restore:
            try:
                session = self.session_manager.load_session(args.restore)
                targets = session.targets
                print(f"Restored session '{args.restore}' with {len(targets)} targets")
            except Exception as exc:
                raise SystemExit(f"Failed to restore session: {exc}")
        
        # Build charsets
        charsets = self.build_charsets(args)
        
        # Generate candidate stream
        try:
            candidates = self.candidate_stream(args, charsets)
        except ValueError as exc:
            raise SystemExit(str(exc))
        
        # Create new session if requested
        if args.save_session and not args.restore:
            session = SessionState(
                session_id=args.save_session,
                created_at=time.time(),
                last_updated=time.time(),
                targets=targets,
                attack_mode=args.attack_mode,
                attack_params=vars(args),
            )
        
        # Run cracking
        try:
            matches, tested, remaining = self.crack(targets, candidates, args)
        except KeyboardInterrupt:
            print("\n[interrupt] stopping early...")
            return
        
        # Update session
        if session:
            session.matches_found.extend(matches)
            session.candidates_tested += tested
            session.cracked_targets.update(target.raw for target, _ in matches)
            session.last_updated = time.time()
            
            if args.save_session:
                self.session_manager.save_session(session)
                print(f"Session saved: {args.save_session}")
        
        # Export session if requested
        if args.export_session and session:
            export_data = self.session_manager.export_session(session, args.export_format)
            with open(args.export_session, 'w', encoding='utf-8') as f:
                f.write(export_data)
            print(f"Session exported to: {args.export_session}")
        
        # Print results
        if matches:
            print("\n[+] recovered credentials:")
            for target, candidate in matches:
                print(f"  {format_match(target, candidate)}")
        else:
            print("\n[!] no matches found.")
        
        print(f"[summary] tested {tested:,} candidates; cracked {len(matches)}/{len(targets)}; remaining {len(remaining)}")
if __name__ == "__main__":
    cli = EnhancedCLI()
    cli.main()
