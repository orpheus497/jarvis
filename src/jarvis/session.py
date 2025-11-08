"""
Jarvis - Session management system.

Created by orpheus497

Manages login sessions for the application.
"""

import json
import os
import secrets
from datetime import datetime, timezone
from typing import Dict, Optional


class Session:
    """Represents a login session."""

    def __init__(self, session_id: str, identity_uid: str):
        self.session_id = session_id
        self.identity_uid = identity_uid
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.last_active = self.created_at
        self.ip_address = "localhost"
        self.enabled = True

    def to_dict(self) -> Dict:
        """Export session to dictionary."""
        return {
            "session_id": self.session_id,
            "identity_uid": self.identity_uid,
            "created_at": self.created_at,
            "last_active": self.last_active,
            "ip_address": self.ip_address,
            "enabled": self.enabled,
        }

    @staticmethod
    def from_dict(data: Dict) -> "Session":
        """Import session from dictionary."""
        session = Session(data["session_id"], data["identity_uid"])
        session.created_at = data.get("created_at", session.created_at)
        session.last_active = data.get("last_active", session.last_active)
        session.ip_address = data.get("ip_address", "localhost")
        session.enabled = data.get("enabled", True)
        return session

    def update_activity(self):
        """Update last active timestamp."""
        self.last_active = datetime.now(timezone.utc).isoformat()


class SessionManager:
    """Manages login sessions."""

    def __init__(self, sessions_file: str):
        self.sessions_file = sessions_file
        self.sessions: Dict[str, Session] = {}  # session_id -> Session
        self.current_session_id: Optional[str] = None
        self._load_sessions()

    def _load_sessions(self):
        """Load sessions from file."""
        if os.path.exists(self.sessions_file):
            try:
                with open(self.sessions_file) as f:
                    data = json.load(f)
                for session_id, session_data in data.items():
                    self.sessions[session_id] = Session.from_dict(session_data)
            except Exception:
                pass

    def save_sessions(self):
        """Save sessions to file."""
        try:
            data = {sid: session.to_dict() for sid, session in self.sessions.items()}
            with open(self.sessions_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def create_session(self, identity_uid: str) -> Session:
        """Create a session."""
        session_id = secrets.token_hex(16)
        session = Session(session_id, identity_uid)
        self.sessions[session_id] = session
        self.current_session_id = session_id
        self.save_sessions()
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        return self.sessions.get(session_id)

    def get_current_session(self) -> Optional[Session]:
        """Get the current active session."""
        if self.current_session_id:
            return self.sessions.get(self.current_session_id)
        return None

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            self.save_sessions()
            return True
        return False

    def update_session_activity(self, session_id: str, ip_address: Optional[str] = None):
        """Update session activity and IP address."""
        session = self.sessions.get(session_id)
        if session:
            session.update_activity()
            if ip_address:
                session.ip_address = ip_address
            self.save_sessions()
