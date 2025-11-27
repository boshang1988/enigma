#!/usr/bin/env python3
"""
Web Interface for Enigma Hashcat

A modern web-based interface for hash cracking operations.
Features:
- Real-time progress monitoring
- Session management
- File upload for wordlists and hash files
- Interactive results display
- Mobile-responsive design
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

from flask import Flask, render_template, request, jsonify, send_file

# Add project root to path
REPO_ROOT = Path(__file__).resolve().parent
import sys
sys.path.insert(0, str(REPO_ROOT))

from python.hashcat_like.enhanced_cli import EnhancedCLI
from python.hashcat_like.core import load_hashes
from python.hashcat_like.attacks import wordlist_candidates, mask_candidates, DEFAULT_CHARSETS


app = Flask(__name__)
app.config['SECRET_KEY'] = 'enigma-hashcat-2025'

# Global state for active cracking sessions
active_sessions: Dict[str, Dict[str, Any]] = {}


class WebCrackingSession:
    """Web-based cracking session with real-time updates."""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.status = "idle"
        self.progress = 0
        self.candidates_tested = 0
        self.matches_found: List[Dict[str, str]] = []
        self.targets: List[Dict[str, Any]] = []
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
    
    def start_cracking(self, config: Dict[str, Any]) -> None:
        """Start cracking in a background thread."""
        self.thread = threading.Thread(target=self._crack_thread, args=(config,))
        self.thread.daemon = True
        self.thread.start()
    
    def _crack_thread(self, config: Dict[str, Any]) -> None:
        """Background thread for cracking."""
        try:
            self.status = "running"
            self.progress = 0
            self.candidates_tested = 0
            self.matches_found = []
            
            # Load hashes
            hash_file = config.get('hash_file')
            if hash_file:
                targets = load_hashes([], [hash_file], config.get('algorithm'))
                self.targets = [
                    {
                        'algorithm': target.algorithm,
                        'hash': target.raw,
                        'cracked': False
                    }
                    for target in targets
                ]
            
            # Generate candidates based on attack mode
            attack_mode = config.get('attack_mode', 'dictionary')
            wordlist_file = config.get('wordlist_file')
            
            candidates = []
            
            if attack_mode == 'dictionary' and wordlist_file:
                candidates = list(wordlist_candidates([wordlist_file], config.get('mutate_mode', 'simple')))
            elif attack_mode == 'mask':
                mask = config.get('mask', '?d?d?d?d')
                candidates = list(mask_candidates(mask, DEFAULT_CHARSETS))
            
            total_candidates = len(candidates)
            
            # Simple cracking simulation
            for i, candidate in enumerate(candidates):
                if self.stop_event.is_set():
                    break
                
                self.candidates_tested = i + 1
                self.progress = (i + 1) / total_candidates * 100 if total_candidates > 0 else 0
                
                # Simulate cracking (in real implementation, this would verify against actual hashes)
                if candidate == "password123":  # Simple demo match
                    self.matches_found.append({
                        'hash': 'demo_hash',
                        'password': candidate,
                        'algorithm': 'sha256'
                    })
                
                time.sleep(0.001)  # Small delay for demo
            
            self.status = "completed"
            
        except Exception as e:
            self.status = "error"
            print(f"Error in cracking session {self.session_id}: {e}")
    
    def stop(self) -> None:
        """Stop the cracking session."""
        self.stop_event.set()
        self.status = "stopped"


@app.route('/')
def index():
    """Main web interface."""
    return render_template('index.html')


@app.route('/api/sessions', methods=['POST'])
def create_session():
    """Create a new cracking session."""
    data = request.json
    session_id = data.get('session_id', f'session_{int(time.time())}')
    
    if session_id in active_sessions:
        return jsonify({'error': 'Session already exists'}), 400
    
    session = WebCrackingSession(session_id)
    active_sessions[session_id] = session
    
    return jsonify({
        'session_id': session_id,
        'status': 'created'
    })


@app.route('/api/sessions/<session_id>/start', methods=['POST'])
def start_session(session_id: str):
    """Start a cracking session."""
    if session_id not in active_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    config = request.json
    session = active_sessions[session_id]
    session.start_cracking(config)
    
    return jsonify({
        'session_id': session_id,
        'status': 'started'
    })


@app.route('/api/sessions/<session_id>/stop', methods=['POST'])
def stop_session(session_id: str):
    """Stop a cracking session."""
    if session_id not in active_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    session = active_sessions[session_id]
    session.stop()
    
    return jsonify({
        'session_id': session_id,
        'status': 'stopped'
    })


@app.route('/api/sessions/<session_id>/status')
def get_session_status(session_id: str):
    """Get session status."""
    if session_id not in active_sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    session = active_sessions[session_id]
    
    return jsonify({
        'session_id': session_id,
        'status': session.status,
        'progress': session.progress,
        'candidates_tested': session.candidates_tested,
        'matches_found': session.matches_found,
        'targets': session.targets
    })


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file uploads for wordlists and hash files."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Create uploads directory
    upload_dir = Path('uploads')
    upload_dir.mkdir(exist_ok=True)
    
    file_path = upload_dir / file.filename
    file.save(file_path)
    
    return jsonify({
        'filename': file.filename,
        'path': str(file_path),
        'size': file_path.stat().st_size
    })


if __name__ == '__main__':
    print("Starting Enigma Hashcat Web Interface...")
    print("Access at: http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)