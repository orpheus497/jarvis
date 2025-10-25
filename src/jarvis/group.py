"""
Jarvis - Group chat management system.

Created by orpheus497

Manages group chats, memberships, and group-specific encryption.
"""

import json
import os
from typing import Dict, List, Optional, Set
from datetime import datetime, timezone

from . import crypto


class GroupMember:
    """Represents a member of a group chat."""
    
    def __init__(self, uid: str, username: str, public_key: str, 
                 fingerprint: str, is_admin: bool = False):
        self.uid = uid
        self.username = username
        self.public_key = public_key
        self.fingerprint = fingerprint
        self.is_admin = is_admin
        self.joined_at = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'uid': self.uid,
            'username': self.username,
            'public_key': self.public_key,
            'fingerprint': self.fingerprint,
            'is_admin': self.is_admin,
            'joined_at': self.joined_at
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'GroupMember':
        """Create from dictionary."""
        member = GroupMember(
            uid=data['uid'],
            username=data['username'],
            public_key=data['public_key'],
            fingerprint=data['fingerprint'],
            is_admin=data.get('is_admin', False)
        )
        member.joined_at = data.get('joined_at', member.joined_at)
        return member


class Group:
    """Represents a group chat."""
    
    def __init__(self, group_id: str, name: str, creator_uid: str):
        self.group_id = group_id
        self.name = name
        self.creator_uid = creator_uid
        self.members: Dict[str, GroupMember] = {}  # uid -> GroupMember
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.description = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage."""
        return {
            'group_id': self.group_id,
            'name': self.name,
            'creator_uid': self.creator_uid,
            'members': {uid: member.to_dict() for uid, member in self.members.items()},
            'created_at': self.created_at,
            'description': self.description
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'Group':
        """Create from dictionary."""
        group = Group(
            group_id=data['group_id'],
            name=data['name'],
            creator_uid=data['creator_uid']
        )
        group.members = {
            uid: GroupMember.from_dict(member_data) 
            for uid, member_data in data.get('members', {}).items()
        }
        group.created_at = data.get('created_at', group.created_at)
        group.description = data.get('description', '')
        return group
    
    def add_member(self, member: GroupMember):
        """Add a member to the group."""
        self.members[member.uid] = member
    
    def remove_member(self, uid: str) -> bool:
        """Remove a member from the group. Returns True if removed."""
        if uid in self.members:
            del self.members[uid]
            return True
        return False
    
    def get_member(self, uid: str) -> Optional[GroupMember]:
        """Get a member by UID."""
        return self.members.get(uid)
    
    def is_member(self, uid: str) -> bool:
        """Check if a UID is a member of the group."""
        return uid in self.members
    
    def is_admin(self, uid: str) -> bool:
        """Check if a member is an admin."""
        member = self.members.get(uid)
        return member.is_admin if member else False
    
    def promote_to_admin(self, uid: str) -> bool:
        """Promote a member to admin. Returns True if successful."""
        member = self.members.get(uid)
        if member:
            member.is_admin = True
            return True
        return False
    
    def get_all_members(self) -> List[GroupMember]:
        """Get all members sorted by join date."""
        return sorted(self.members.values(), key=lambda m: m.joined_at)
    
    def get_member_uids(self) -> Set[str]:
        """Get set of all member UIDs."""
        return set(self.members.keys())


class GroupManager:
    """Manages group chats and their persistent storage."""
    
    def __init__(self, groups_file: str):
        self.groups_file = groups_file
        self.groups: Dict[str, Group] = {}  # group_id -> Group
        self._load_groups()
    
    def _load_groups(self):
        """Load groups from file."""
        if os.path.exists(self.groups_file):
            try:
                with open(self.groups_file, 'r') as f:
                    data = json.load(f)
                for group_id, group_data in data.items():
                    self.groups[group_id] = Group.from_dict(group_data)
            except Exception as e:
                pass
    
    def save_groups(self):
        """Save groups to file."""
        try:
            data = {group_id: group.to_dict() for group_id, group in self.groups.items()}
            with open(self.groups_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            pass
    
    def create_group(self, name: str, creator_uid: str, creator_username: str,
                    creator_public_key: str, creator_fingerprint: str) -> Group:
        """
        Create a group with a unique group ID.
        Creator is automatically added as admin.
        """
        # Generate unique group ID
        group_id = crypto.generate_group_uid()
        
        # Create group
        group = Group(group_id, name, creator_uid)
        
        # Add creator as admin member
        creator_member = GroupMember(
            uid=creator_uid,
            username=creator_username,
            public_key=creator_public_key,
            fingerprint=creator_fingerprint,
            is_admin=True
        )
        group.add_member(creator_member)
        
        # Save
        self.groups[group_id] = group
        self.save_groups()
        
        return group
    
    def delete_group(self, group_id: str) -> bool:
        """Delete a group. Returns True if deleted."""
        if group_id in self.groups:
            del self.groups[group_id]
            self.save_groups()
            return True
        return False
    
    def get_group(self, group_id: str) -> Optional[Group]:
        """Get a group by ID."""
        return self.groups.get(group_id)
    
    def get_all_groups(self) -> List[Group]:
        """Get all groups sorted by creation date."""
        return sorted(self.groups.values(), key=lambda g: g.created_at, reverse=True)
    
    def get_user_groups(self, uid: str) -> List[Group]:
        """Get all groups where a user is a member."""
        user_groups = []
        for group in self.groups.values():
            if group.is_member(uid):
                user_groups.append(group)
        return sorted(user_groups, key=lambda g: g.created_at, reverse=True)
    
    def add_member_to_group(self, group_id: str, member: GroupMember) -> bool:
        """Add a member to a group. Returns True if successful."""
        group = self.groups.get(group_id)
        if group:
            group.add_member(member)
            self.save_groups()
            return True
        return False
    
    def remove_member_from_group(self, group_id: str, uid: str) -> bool:
        """Remove a member from a group. Returns True if successful."""
        group = self.groups.get(group_id)
        if group and group.remove_member(uid):
            self.save_groups()
            return True
        return False
    
    def update_group_name(self, group_id: str, name: str) -> bool:
        """Update group name. Returns True if successful."""
        group = self.groups.get(group_id)
        if group:
            group.name = name
            self.save_groups()
            return True
        return False
    
    def update_group_description(self, group_id: str, description: str) -> bool:
        """Update group description. Returns True if successful."""
        group = self.groups.get(group_id)
        if group:
            group.description = description
            self.save_groups()
            return True
        return False
