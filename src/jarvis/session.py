"""
Jarvis - Session management system for parent-child identity relationships.

Created by orpheus497

Manages multi-session support with parent-child relationships for
maintaining strong P2P server connections.
"""

import json
import os
import secrets
from typing import Dict, List, Optional
from datetime import datetime, timezone

from . import crypto


class Session:
    """Represents a login session (parent or child)."""
    
    def __init__(self, session_id: str, identity_uid: str, is_parent: bool = True,
                 parent_session_id: Optional[str] = None):
        self.session_id = session_id
        self.identity_uid = identity_uid
        self.is_parent = is_parent
        self.parent_session_id = parent_session_id
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.last_active = self.created_at
        self.ip_address = "localhost"  # Will be updated with actual IP
        self.enabled = True
    
    def to_dict(self) -> Dict:
        """Export session to dictionary."""
        return {
            'session_id': self.session_id,
            'identity_uid': self.identity_uid,
            'is_parent': self.is_parent,
            'parent_session_id': self.parent_session_id,
            'created_at': self.created_at,
            'last_active': self.last_active,
            'ip_address': self.ip_address,
            'enabled': self.enabled
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'Session':
        """Import session from dictionary."""
        session = Session(
            data['session_id'],
            data['identity_uid'],
            data.get('is_parent', True),
            data.get('parent_session_id')
        )
        session.created_at = data.get('created_at', session.created_at)
        session.last_active = data.get('last_active', session.last_active)
        session.ip_address = data.get('ip_address', 'localhost')
        session.enabled = data.get('enabled', True)
        return session
    
    def update_activity(self):
        """Update last active timestamp."""
        self.last_active = datetime.now(timezone.utc).isoformat()


class SessionManager:
    """Manages sessions with parent-child relationships."""
    
    def __init__(self, sessions_file: str):
        self.sessions_file = sessions_file
        self.sessions: Dict[str, Session] = {}  # session_id -> Session
        self.current_session_id: Optional[str] = None
        self._load_sessions()
    
    def _load_sessions(self):
        """Load sessions from encrypted file."""
        if os.path.exists(self.sessions_file):
            try:
                with open(self.sessions_file, 'r') as f:
                    data = json.load(f)
                for session_id, session_data in data.items():
                    self.sessions[session_id] = Session.from_dict(session_data)
            except Exception:
                pass
    
    def save_sessions(self):
        """Save sessions to encrypted file."""
        try:
            data = {sid: session.to_dict() for sid, session in self.sessions.items()}
            with open(self.sessions_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def create_parent_session(self, identity_uid: str) -> Session:
        """Create a parent session."""
        session_id = secrets.token_hex(16)
        session = Session(session_id, identity_uid, is_parent=True)
        self.sessions[session_id] = session
        self.current_session_id = session_id
        self.save_sessions()
        return session
    
    def create_child_session(self, identity_uid: str, parent_session_id: str) -> Session:
        """Create a child session linked to a parent."""
        session_id = secrets.token_hex(16)
        session = Session(session_id, identity_uid, is_parent=False, 
                         parent_session_id=parent_session_id)
        self.sessions[session_id] = session
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
    
    def get_child_sessions(self, parent_session_id: str) -> List[Session]:
        """Get all child sessions for a parent."""
        children = []
        for session in self.sessions.values():
            if session.parent_session_id == parent_session_id:
                children.append(session)
        return sorted(children, key=lambda s: s.created_at, reverse=True)
    
    def disable_session(self, session_id: str) -> bool:
        """Disable a session."""
        session = self.sessions.get(session_id)
        if session:
            session.enabled = False
            self.save_sessions()
            return True
        return False
    
    def enable_session(self, session_id: str) -> bool:
        """Enable a session."""
        session = self.sessions.get(session_id)
        if session:
            session.enabled = True
            self.save_sessions()
            return True
        return False
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its children."""
        if session_id in self.sessions:
            # Delete all child sessions first
            children = self.get_child_sessions(session_id)
            for child in children:
                del self.sessions[child.session_id]
            
            # Delete the session itself
            del self.sessions[session_id]
            self.save_sessions()
            return True
        return False
    
    def is_parent_session(self) -> bool:
        """Check if current session is a parent session."""
        session = self.get_current_session()
        return session.is_parent if session else False
    
    def update_session_activity(self, session_id: str, ip_address: Optional[str] = None):
        """Update session activity and IP address."""
        session = self.sessions.get(session_id)
        if session:
            session.update_activity()
            if ip_address:
                session.ip_address = ip_address
            self.save_sessions()
