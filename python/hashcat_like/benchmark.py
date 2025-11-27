"""
Benchmarking module for Enigma Hashcat

Features:
- Algorithm performance testing
- System capability assessment
- GPU detection and benchmarking
- Performance optimization recommendations
"""

from __future__ import annotations

import hashlib
import time
from typing import Dict, List, Optional, Tuple

from .core import HashTarget, SimpleHashTarget


class BenchmarkResult:
    """Results from a benchmark run."""
    
    def __init__(self, algorithm: str, hashes_per_second: float, test_duration: float):
        self.algorithm = algorithm
        self.hashes_per_second = hashes_per_second
        self.test_duration = test_duration
    
    def __str__(self) -> str:
        return f"{self.algorithm}: {self.hashes_per_second:,.0f} H/s"


class BenchmarkSuite:
    """Comprehensive benchmarking for hash algorithms."""
    
    def __init__(self):
        self.test_password = "benchmark_password_123"
        self.test_salt = b"benchmark_salt"
        self.iterations = 10000
    
    def benchmark_simple_hash(self, algorithm: str) -> BenchmarkResult:
        """Benchmark a simple hash algorithm."""
        start_time = time.time()
        
        for i in range(self.iterations):
            test_data = f"{self.test_password}{i}".encode()
            hashlib.new(algorithm, test_data).hexdigest()
        
        end_time = time.time()
        duration = end_time - start_time
        hashes_per_second = self.iterations / duration
        
        return BenchmarkResult(algorithm, hashes_per_second, duration)
    
    def benchmark_pbkdf2(self, algorithm: str) -> BenchmarkResult:
        """Benchmark PBKDF2 algorithm."""
        import hashlib
        
        start_time = time.time()
        
        for i in range(self.iterations // 10):  # PBKDF2 is slower
            test_password = f"{self.test_password}{i}"
            hashlib.pbkdf2_hmac(
                algorithm.replace("pbkdf2-", ""),
                test_password.encode(),
                self.test_salt,
                1000,  # Reduced iterations for benchmarking
            )
        
        end_time = time.time()
        duration = end_time - start_time
        hashes_per_second = (self.iterations // 10) / duration
        
        return BenchmarkResult(algorithm, hashes_per_second, duration)
    
    def benchmark_scrypt(self) -> BenchmarkResult:
        """Benchmark scrypt algorithm."""
        import hashlib
        
        start_time = time.time()
        
        for i in range(self.iterations // 100):  # scrypt is much slower
            test_password = f"{self.test_password}{i}"
            hashlib.scrypt(
                test_password.encode(),
                salt=self.test_salt,
                n=1024,  # Reduced for benchmarking
                r=8,
                p=1,
            )
        
        end_time = time.time()
        duration = end_time - start_time
        hashes_per_second = (self.iterations // 100) / duration
        
        return BenchmarkResult("scrypt", hashes_per_second, duration)
    
    def run_full_benchmark(self) -> Dict[str, BenchmarkResult]:
        """Run comprehensive benchmark of all supported algorithms."""
        results = {}
        
        # Simple hashes
        simple_hashes = ["md5", "sha1", "sha256", "sha512", "sha3-256", "blake2b"]
        
        for algo in simple_hashes:
            print(f"Benchmarking {algo}...")
            try:
                results[algo] = self.benchmark_simple_hash(algo)
            except Exception as e:
                print(f"  Failed to benchmark {algo}: {e}")
        
        # PBKDF2 variants
        pbkdf2_hashes = ["pbkdf2-sha256", "pbkdf2-sha512"]
        
        for algo in pbkdf2_hashes:
            print(f"Benchmarking {algo}...")
            try:
                results[algo] = self.benchmark_pbkdf2(algo)
            except Exception as e:
                print(f"  Failed to benchmark {algo}: {e}")
        
        # Scrypt
        print("Benchmarking scrypt...")
        try:
            results["scrypt"] = self.benchmark_scrypt()
        except Exception as e:
            print(f"  Failed to benchmark scrypt: {e}")
        
        return results
    
    def print_results(self, results: Dict[str, BenchmarkResult]) -> None:
        """Print benchmark results in a formatted table."""
        print("\n" + "="*60)
        print("ENIGMA HASHCAT BENCHMARK RESULTS")
        print("="*60)
        
        # Sort by performance (descending)
        sorted_results = sorted(
            results.items(),
            key=lambda x: x[1].hashes_per_second,
            reverse=True
        )
        
        for algo, result in sorted_results:
            print(f"{algo:15} {result.hashes_per_second:>12,.0f} H/s")
        
        print("="*60)
        
        # Performance recommendations
        fastest = sorted_results[0] if sorted_results else None
        if fastest:
            print(f"\nFastest algorithm: {fastest[0]} ({fastest[1].hashes_per_second:,.0f} H/s)")


def detect_gpu() -> Optional[Dict[str, str]]:
    """Detect available GPU hardware."""
    try:
        import subprocess
        
        # Try to detect NVIDIA GPU
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                gpus = []
                for line in lines:
                    if ',' in line:
                        name, memory = line.split(',', 1)
                        gpus.append({
                            'vendor': 'nvidia',
                            'name': name.strip(),
                            'memory': memory.strip(),
                        })
                return {'nvidia': gpus}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Try to detect AMD GPU
        try:
            result = subprocess.run(
                ["rocm-smi", "--showproductname", "--showmeminfo", "vram"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            if result.returncode == 0:
                # Parse ROCm output (simplified)
                return {'amd': [{'vendor': 'amd', 'name': 'AMD GPU', 'memory': 'unknown'}]}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
    except Exception:
        pass
    
    return None


def system_info() -> Dict[str, str]:
    """Get system information for performance assessment."""
    import multiprocessing
    import platform
    import psutil
    
    info = {
        'platform': platform.system(),
        'platform_version': platform.version(),
        'processor': platform.processor(),
        'cpu_cores': str(multiprocessing.cpu_count()),
        'total_memory': f"{psutil.virtual_memory().total // (1024**3)} GB",
    }
    
    # Detect GPU
    gpu_info = detect_gpu()
    if gpu_info:
        info['gpu'] = str(gpu_info)
    
    return info


def estimate_cracking_time(
    algorithm: str,
    attack_complexity: int,
    benchmark_results: Dict[str, BenchmarkResult],
) -> Optional[float]:
    """Estimate time to crack based on algorithm performance and attack complexity."""
    if algorithm not in benchmark_results:
        return None
    
    result = benchmark_results[algorithm]
    hashes_per_second = result.hashes_per_second
    
    if hashes_per_second == 0:
        return None
    
    return attack_complexity / hashes_per_second


def format_cracking_time(seconds: float) -> str:
    """Format cracking time estimate in human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    else:
        return f"{seconds/31536000:.1f} years"