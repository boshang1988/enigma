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
from .gpu_acceleration import detect_gpu, get_gpu_performance


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
        hashes_per_second = self.iterations / duration if duration > 0 else 0
        
        return BenchmarkResult(algorithm, hashes_per_second, duration)
    
    def benchmark_pbkdf2(self, algorithm: str, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark PBKDF2 algorithm."""
        import hashlib
        
        start_time = time.time()
        
        for i in range(iterations):
            hashlib.pbkdf2_hmac(
                algorithm.replace("pbkdf2-", ""),
                self.test_password.encode(),
                self.test_salt,
                iterations=1000
            )
        
        end_time = time.time()
        duration = end_time - start_time
        hashes_per_second = iterations / duration if duration > 0 else 0
        
        return BenchmarkResult(algorithm, hashes_per_second, duration)
    
    def benchmark_bcrypt(self, rounds: int = 12) -> BenchmarkResult:
        """Benchmark bcrypt algorithm."""
        try:
            import bcrypt
            
            start_time = time.time()
            
            for i in range(100):  # bcrypt is slow, so fewer iterations
                bcrypt.hashpw(self.test_password.encode(), bcrypt.gensalt(rounds=rounds))
            
            end_time = time.time()
            duration = end_time - start_time
            hashes_per_second = 100 / duration if duration > 0 else 0
            
            return BenchmarkResult(f"bcrypt-{rounds}", hashes_per_second, duration)
        except ImportError:
            return BenchmarkResult(f"bcrypt-{rounds}", 0, 0)
    
    def benchmark_argon2(self, variant: str = "argon2id") -> BenchmarkResult:
        """Benchmark Argon2 algorithm."""
        try:
            from argon2 import PasswordHasher
            
            ph = PasswordHasher()
            start_time = time.time()
            
            for i in range(100):  # Argon2 is slow, so fewer iterations
                ph.hash(self.test_password)
            
            end_time = time.time()
            duration = end_time - start_time
            hashes_per_second = 100 / duration if duration > 0 else 0
            
            return BenchmarkResult(variant, hashes_per_second, duration)
        except ImportError:
            return BenchmarkResult(variant, 0, 0)
    
    def benchmark_scrypt(self) -> BenchmarkResult:
        """Benchmark scrypt algorithm."""
        import hashlib
        
        start_time = time.time()
        
        for i in range(100):  # scrypt is slow, so fewer iterations
            hashlib.scrypt(
                self.test_password.encode(),
                salt=self.test_salt,
                n=16384,
                r=8,
                p=1
            )
        
        end_time = time.time()
        duration = end_time - start_time
        hashes_per_second = 100 / duration if duration > 0 else 0
        
        return BenchmarkResult("scrypt", hashes_per_second, duration)
    
    def run_all(self) -> Dict[str, BenchmarkResult]:
        """Run comprehensive benchmarks for all supported algorithms."""
        print("Running comprehensive benchmarks...")
        print("=" * 60)
        
        results = {}
        
        # Simple hashes
        simple_hashes = ["md5", "sha1", "sha256", "sha512", "sha3-256", "blake2b"]
        for algo in simple_hashes:
            print(f"Benchmarking {algo}...", end=" ")
            result = self.benchmark_simple_hash(algo)
            results[algo] = result
            print(f"{result.hashes_per_second:,.0f} H/s")
        
        # PBKDF2 variants
        pbkdf2_algos = ["pbkdf2-sha256", "pbkdf2-sha512"]
        for algo in pbkdf2_algos:
            print(f"Benchmarking {algo}...", end=" ")
            result = self.benchmark_pbkdf2(algo, iterations=100)
            results[algo] = result
            print(f"{result.hashes_per_second:,.1f} H/s")
        
        # Slow hashes
        print(f"Benchmarking bcrypt...", end=" ")
        bcrypt_result = self.benchmark_bcrypt()
        results["bcrypt"] = bcrypt_result
        print(f"{bcrypt_result.hashes_per_second:,.1f} H/s")
        
        print(f"Benchmarking argon2id...", end=" ")
        argon2_result = self.benchmark_argon2()
        results["argon2id"] = argon2_result
        print(f"{argon2_result.hashes_per_second:,.1f} H/s")
        
        print(f"Benchmarking scrypt...", end=" ")
        scrypt_result = self.benchmark_scrypt()
        results["scrypt"] = scrypt_result
        print(f"{scrypt_result.hashes_per_second:,.1f} H/s")
        
        # GPU benchmarks
        print("\nGPU Performance:")
        gpu_perf = get_gpu_performance()
        for device_id, hps in gpu_perf.items():
            print(f"  GPU {device_id}: {hps:,.0f} H/s (estimated)")
        
        print("=" * 60)
        print("Benchmark complete!")
        
        return results


def system_info() -> Dict[str, str]:
    """Get comprehensive system information."""
    import multiprocessing
    import platform
    import psutil
    
    info = {
        'platform': platform.system(),
        'platform_version': platform.version(),
        'processor': platform.processor(),
        'cpu_cores': str(multiprocessing.cpu_count()),
        'total_memory': f"{psutil.virtual_memory().total // (1024**3)} GB",
        'available_memory': f"{psutil.virtual_memory().available // (1024**3)} GB",
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