"""
Jarvis - Message storage and management.

Created by orpheus497

Handles message persistence, conversation history, and retrieval for both
direct messages and group chats.
"""

import json
import os
import uuid
from typing import Dict, List, Optional
from datetime import datetime, timezone


class Message:
    """Represents a message in a conversation."""
    
    def __init__(self, contact_uid: str, content: str, sent_by_me: bool,
                 timestamp: Optional[str] = None, message_id: Optional[str] = None,
                 delivered: bool = False, read: bool = False, 
                 group_id: Optional[str] = None, sender_uid: Optional[str] = None):
        self.message_id = message_id or str(uuid.uuid4())
        self.contact_uid = contact_uid  # For direct messages
        self.content = content
        self.sent_by_me = sent_by_me
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.delivered = delivered
        self.read = read
        self.encrypted = True
        
        # Group chat specific fields
        self.group_id = group_id
        self.sender_uid = sender_uid  # UID of the actual sender in group chat
    
    def to_dict(self) -> Dict:
        """Convert message to dictionary for storage."""
        return {
            'message_id': self.message_id,
            'contact_uid': self.contact_uid,
            'content': self.content,
            'sent_by_me': self.sent_by_me,
            'timestamp': self.timestamp,
            'delivered': self.delivered,
            'read': self.read,
            'encrypted': self.encrypted,
            'group_id': self.group_id,
            'sender_uid': self.sender_uid
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'Message':
        """Create message from dictionary."""
        msg = Message(
            contact_uid=data['contact_uid'],
            content=data['content'],
            sent_by_me=data['sent_by_me'],
            timestamp=data['timestamp'],
            message_id=data['message_id'],
            delivered=data.get('delivered', False),
            read=data.get('read', False),
            group_id=data.get('group_id'),
            sender_uid=data.get('sender_uid')
        )
        msg.encrypted = data.get('encrypted', True)
        return msg
    
    def mark_delivered(self):
        """Mark message as delivered."""
        self.delivered = True
    
    def mark_read(self):
        """Mark message as read."""
        self.read = True
    
    def is_group_message(self) -> bool:
        """Check if this is a group message."""
        return self.group_id is not None


class MessageStore:
    """Manages message storage and retrieval."""
    
    def __init__(self, messages_file: str):
        self.messages_file = messages_file
        self.messages: List[Message] = []
        self._load_messages()
    
    def _load_messages(self):
        """Load messages from file."""
        if os.path.exists(self.messages_file):
            try:
                with open(self.messages_file, 'r') as f:
                    data = json.load(f)
                self.messages = [Message.from_dict(msg_data) for msg_data in data]
            except Exception as e:
                pass
    
    def save_messages(self):
        """Save messages to file."""
        try:
            data = [msg.to_dict() for msg in self.messages]
            with open(self.messages_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            pass
    
    def add_message(self, message: Message):
        """Add a message to the store."""
        self.messages.append(message)
        self.save_messages()
    
    def get_conversation(self, contact_uid: str, limit: Optional[int] = None) -> List[Message]:
        """
        Get all direct messages for a specific contact.
        Returns messages sorted by timestamp (oldest first).
        """
        conversation = [
            msg for msg in self.messages 
            if msg.contact_uid == contact_uid and msg.group_id is None
        ]
        conversation.sort(key=lambda m: m.timestamp)
        if limit:
            return conversation[-limit:]
        return conversation
    
    def get_group_conversation(self, group_id: str, limit: Optional[int] = None) -> List[Message]:
        """
        Get all messages for a specific group.
        Returns messages sorted by timestamp (oldest first).
        """
        conversation = [
            msg for msg in self.messages 
            if msg.group_id == group_id
        ]
        conversation.sort(key=lambda m: m.timestamp)
        if limit:
            return conversation[-limit:]
        return conversation
    
    def get_recent_conversations(self, limit: int = 10) -> List[str]:
        """
        Get list of contact UIDs with recent direct conversations.
        Returns most recent conversations first.
        """
        conversations = {}
        for msg in self.messages:
            if msg.group_id is None:  # Only direct messages
                if msg.contact_uid not in conversations:
                    conversations[msg.contact_uid] = msg.timestamp
                else:
                    if msg.timestamp > conversations[msg.contact_uid]:
                        conversations[msg.contact_uid] = msg.timestamp
        
        sorted_contacts = sorted(conversations.items(), key=lambda x: x[1], reverse=True)
        return [contact for contact, _ in sorted_contacts[:limit]]
    
    def get_recent_group_conversations(self, limit: int = 10) -> List[str]:
        """
        Get list of group IDs with recent conversations.
        Returns most recent conversations first.
        """
        conversations = {}
        for msg in self.messages:
            if msg.group_id is not None:  # Only group messages
                if msg.group_id not in conversations:
                    conversations[msg.group_id] = msg.timestamp
                else:
                    if msg.timestamp > conversations[msg.group_id]:
                        conversations[msg.group_id] = msg.timestamp
        
        sorted_groups = sorted(conversations.items(), key=lambda x: x[1], reverse=True)
        return [group for group, _ in sorted_groups[:limit]]
    
    def mark_as_read(self, contact_uid: str):
        """Mark all direct messages from a contact as read."""
        modified = False
        for msg in self.messages:
            if (msg.contact_uid == contact_uid and 
                msg.group_id is None and 
                not msg.sent_by_me and 
                not msg.read):
                msg.mark_read()
                modified = True
        if modified:
            self.save_messages()
    
    def mark_group_as_read(self, group_id: str):
        """Mark all group messages as read."""
        modified = False
        for msg in self.messages:
            if msg.group_id == group_id and not msg.sent_by_me and not msg.read:
                msg.mark_read()
                modified = True
        if modified:
            self.save_messages()
    
    def get_unread_count(self, contact_uid: str) -> int:
        """Get count of unread direct messages from a contact."""
        return sum(
            1 for msg in self.messages 
            if (msg.contact_uid == contact_uid and 
                msg.group_id is None and 
                not msg.sent_by_me and 
                not msg.read)
        )
    
    def get_group_unread_count(self, group_id: str) -> int:
        """Get count of unread messages in a group."""
        return sum(
            1 for msg in self.messages 
            if msg.group_id == group_id and not msg.sent_by_me and not msg.read
        )
    
    def get_total_unread_count(self) -> int:
        """Get total count of unread messages from all contacts and groups."""
        return sum(1 for msg in self.messages if not msg.sent_by_me and not msg.read)
    
    def delete_conversation(self, contact_uid: str):
        """Delete all direct messages for a contact."""
        self.messages = [
            msg for msg in self.messages 
            if not (msg.contact_uid == contact_uid and msg.group_id is None)
        ]
        self.save_messages()
    
    def delete_group_conversation(self, group_id: str):
        """Delete all messages for a group."""
        self.messages = [msg for msg in self.messages if msg.group_id != group_id]
        self.save_messages()
    
    def search_messages(self, query: str, contact_uid: Optional[str] = None, 
                       group_id: Optional[str] = None) -> List[Message]:
        """
        Search messages by content.
        Can filter by contact UID or group ID.
        """
        query_lower = query.lower()
        results = []
        for msg in self.messages:
            if query_lower in msg.content.lower():
                if contact_uid and msg.contact_uid != contact_uid:
                    continue
                if group_id and msg.group_id != group_id:
                    continue
                results.append(msg)
        return results
    
    def delete_all_messages(self) -> bool:
        """
        Delete all messages and the messages file.
        Returns True if successful.
        """
        self.messages.clear()
        if os.path.exists(self.messages_file):
            try:
                os.remove(self.messages_file)
                return True
            except Exception:
                return False
        return True
