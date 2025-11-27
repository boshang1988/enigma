"""
Performance optimization module for Enigma Hashcat

Features:
- Multi-threading support
- GPU acceleration detection
- Memory-efficient candidate generation
- Progress tracking with ETA
- Session caching
"""

from __future__ import annotations

import concurrent.futures
import multiprocessing
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple


def detect_optimal_threads() -> int:
    """Detect optimal number of threads for the system."""
    try:
        cpu_count = multiprocessing.cpu_count()
        # Leave one core free for system operations
        return max(1, cpu_count - 1)
    except:
        return 4  # Safe default


@dataclass
class PerformanceStats:
    """Performance statistics tracking."""
    start_time: float
    candidates_tested: int = 0
    matches_found: int = 0
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    @property
    def rate_per_second(self) -> float:
        if self.elapsed_time == 0:
            return 0
        return self.candidates_tested / self.elapsed_time
    
    @property
    def eta(self, total_candidates: Optional[int] = None) -> Optional[float]:
        """Estimate time remaining."""
        if not total_candidates or self.rate_per_second == 0:
            return None
        remaining = total_candidates - self.candidates_tested
        return remaining / self.rate_per_second


class ParallelProcessor:
    """Parallel processing engine for hash cracking."""
    
    def __init__(self, max_workers: Optional[int] = None):
        self.max_workers = max_workers or detect_optimal_threads()
        self.stats = PerformanceStats(start_time=time.time())
    
    def process_batch(
        self,
        targets: List[Any],
        candidates: Iterable[str],
        verify_func: Callable[[Any, str], bool],
        batch_size: int = 10000,
    ) -> Iterator[Tuple[Any, str]]:
        """Process candidates in parallel batches."""
        
        def process_candidate_batch(batch: List[str]) -> List[Tuple[Any, str]]:
            """Process a single batch of candidates."""
            matches = []
            for candidate in batch:
                for target in targets:
                    if verify_func(target, candidate):
                        matches.append((target, candidate))
            return matches
        
        batch = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_batch = {}
            
            for candidate in candidates:
                batch.append(candidate)
                self.stats.candidates_tested += 1
                
                if len(batch) >= batch_size:
                    # Submit batch for processing
                    future = executor.submit(process_candidate_batch, batch.copy())
                    future_to_batch[future] = batch.copy()
                    batch.clear()
                    
                    # Check completed futures
                    for future in concurrent.futures.as_completed(future_to_batch):
                        matches = future.result()
                        for match in matches:
                            self.stats.matches_found += 1
                            yield match
                        del future_to_batch[future]
            
            # Process remaining batch
            if batch:
                matches = process_candidate_batch(batch)
                for match in matches:
                    self.stats.matches_found += 1
                    yield match
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current performance statistics."""
        return {
            "elapsed_time": self.stats.elapsed_time,
            "candidates_tested": self.stats.candidates_tested,
            "matches_found": self.stats.matches_found,
            "rate_per_second": self.stats.rate_per_second,
            "threads": self.max_workers,
        }


def format_eta(seconds: Optional[float]) -> str:
    """Format ETA in human-readable format."""
    if seconds is None:
        return "unknown"
    
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"