"""
Session management for Enigma Hashcat

Features:
- Save/restore cracking sessions
- Resume interrupted attacks
- Session statistics and progress tracking
- Export/import session data
"""

from __future__ import annotations

import json
import pickle
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .core import HashTarget


@dataclass
class SessionState:
    """Session state for saving/restoring cracking progress."""
    
    # Session metadata
    session_id: str
    created_at: float
    last_updated: float
    
    # Attack configuration
    targets: List[HashTarget]
    attack_mode: str
    attack_params: Dict[str, Any]
    
    # Progress tracking
    candidates_tested: int = 0
    matches_found: List[Tuple[HashTarget, str]] = field(default_factory=list)
    cracked_targets: Set[str] = field(default_factory=set)
    
    # Performance stats
    start_time: float = field(default_factory=time.time)
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    @property
    def rate_per_second(self) -> float:
        if self.elapsed_time == 0:
            return 0
        return self.candidates_tested / self.elapsed_time
    
    def add_match(self, target: HashTarget, candidate: str) -> None:
        """Add a successful match to the session."""
        self.matches_found.append((target, candidate))
        self.cracked_targets.add(target.raw)
        self.last_updated = time.time()
    
    def update_progress(self, candidates_tested: int) -> None:
        """Update progress counters."""
        self.candidates_tested = candidates_tested
        self.last_updated = time.time()


class SessionManager:
    """Manager for hash cracking sessions."""
    
    def __init__(self, session_dir: Optional[str] = None):
        self.session_dir = Path(session_dir or "~/.enigma_sessions").expanduser()
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.active_sessions: Dict[str, SessionState] = {}
    
    def create_session(
        self,
        targets: List[HashTarget],
        attack_mode: str,
        attack_params: Dict[str, Any],
        session_id: Optional[str] = None,
    ) -> SessionState:
        """Create a new cracking session."""
        if session_id is None:
            session_id = f"session_{int(time.time())}"
        
        session = SessionState(
            session_id=session_id,
            created_at=time.time(),
            last_updated=time.time(),
            targets=targets,
            attack_mode=attack_mode,
            attack_params=attack_params,
        )
        
        self.active_sessions[session_id] = session
        return session
    
    def save_session(self, session: SessionState, filename: Optional[str] = None) -> str:
        """Save session to disk."""
        if filename is None:
            filename = f"{session.session_id}.json"
        
        filepath = self.session_dir / filename
        
        # Convert session to serializable format
        session_data = {
            "session_id": session.session_id,
            "created_at": session.created_at,
            "last_updated": session.last_updated,
            "targets": [target.raw for target in session.targets],
            "attack_mode": session.attack_mode,
            "attack_params": session.attack_params,
            "candidates_tested": session.candidates_tested,
            "matches_found": [
                (target.raw, candidate) for target, candidate in session.matches_found
            ],
            "cracked_targets": list(session.cracked_targets),
            "start_time": session.start_time,
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(session_data, f, indent=2)
        
        return str(filepath)
    
    def load_session(self, filename: str) -> SessionState:
        """Load session from disk."""
        from .core import load_hashes
        
        filepath = self.session_dir / filename
        
        with open(filepath, 'r', encoding='utf-8') as f:
            session_data = json.load(f)
        
        # Reconstruct targets
        targets = load_hashes(
            inline_hashes=session_data["targets"],
            hash_files=[],
            default_algorithm=None,
            salt_position="prefix",
        )
        
        # Create session
        session = SessionState(
            session_id=session_data["session_id"],
            created_at=session_data["created_at"],
            last_updated=session_data["last_updated"],
            targets=targets,
            attack_mode=session_data["attack_mode"],
            attack_params=session_data["attack_params"],
            candidates_tested=session_data["candidates_tested"],
            start_time=session_data["start_time"],
        )
        
        # Reconstruct matches
        target_map = {target.raw: target for target in targets}
        for target_raw, candidate in session_data["matches_found"]:
            if target_raw in target_map:
                session.add_match(target_map[target_raw], candidate)
        
        # Reconstruct cracked targets
        session.cracked_targets = set(session_data["cracked_targets"])
        
        self.active_sessions[session.session_id] = session
        return session
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all saved sessions."""
        sessions = []
        
        for filepath in self.session_dir.glob("*.json"):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)
                
                sessions.append({
                    "filename": filepath.name,
                    "session_id": session_data["session_id"],
                    "created_at": session_data["created_at"],
                    "last_updated": session_data["last_updated"],
                    "targets_count": len(session_data["targets"]),
                    "cracked_count": len(session_data["matches_found"]),
                    "candidates_tested": session_data["candidates_tested"],
                })
            except Exception:
                continue
        
        return sessions
    
    def delete_session(self, filename: str) -> bool:
        """Delete a saved session."""
        filepath = self.session_dir / filename
        
        if filepath.exists():
            filepath.unlink()
            return True
        
        return False
    
    def export_session(self, session: SessionState, format: str = "json") -> str:
        """Export session data in various formats."""
        if format == "json":
            return self._export_json(session)
        elif format == "csv":
            return self._export_csv(session)
        elif format == "hashcat":
            return self._export_hashcat(session)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_json(self, session: SessionState) -> str:
        """Export session as JSON."""
        export_data = {
            "session": {
                "id": session.session_id,
                "created": session.created_at,
                "updated": session.last_updated,
                "elapsed_time": session.elapsed_time,
                "candidates_tested": session.candidates_tested,
                "rate_per_second": session.rate_per_second,
            },
            "results": [
                {
                    "hash": target.raw,
                    "password": candidate,
                    "algorithm": target.algorithm,
                }
                for target, candidate in session.matches_found
            ],
            "remaining_targets": [
                target.raw for target in session.targets
                if target.raw not in session.cracked_targets
            ],
        }
        
        return json.dumps(export_data, indent=2)
    
    def _export_csv(self, session: SessionState) -> str:
        """Export session as CSV."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(["hash", "password", "algorithm"])
        
        # Write data
        for target, candidate in session.matches_found:
            writer.writerow([target.raw, candidate, target.algorithm])
        
        return output.getvalue()
    
    def _export_hashcat(self, session: SessionState) -> str:
        """Export cracked passwords in hashcat potfile format."""
        lines = []
        for target, candidate in session.matches_found:
            lines.append(f"{target.raw}:{candidate}")
        
        return "\n".join(lines)