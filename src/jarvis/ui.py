"""
Jarvis - Textual-based terminal user interface.

Created by orpheus497
"""

import os
import sys
import asyncio
import time
import base64
import json
from typing import Optional, List, Dict
from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Static, Label, Input, Button, Header, Footer, 
    ListView, ListItem, RichLog, DataTable
)
from textual.reactive import reactive
from textual.screen import Screen, ModalScreen
from textual import events
from textual.message import Message
from rich.text import Text
from rich.console import RenderableType
from rich.panel import Panel
from rich.table import Table as RichTable

from . import crypto
from .identity import IdentityManager, Identity
from .contact import ContactManager, Contact
from .message import MessageStore, Message as MessageModel
from .group import GroupManager, Group, GroupMember
from .network import NetworkManager, ConnectionState
from .notification import get_notification_manager
from .utils import (
    format_timestamp, format_timestamp_relative, validate_port,
    validate_ip, validate_hostname, format_fingerprint, truncate_string
)

# ASCII Banner for Jarvis
JARVIS_BANNER = """░        ░░░      ░░░       ░░░  ░░░░  ░░        ░░░      ░░
▒▒▒▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒▒▒
▓▓▓▓▓▓▓  ▓▓  ▓▓▓▓  ▓▓       ▓▓▓▓  ▓▓  ▓▓▓▓▓▓  ▓▓▓▓▓▓      ▓▓
█  ████  ██        ██  ███  █████    ███████  ███████████  █
██      ███  ████  ██  ████  █████  █████        ███      ██"""

# Color sequence for animated banner
BANNER_COLORS = ["cyan", "blue", "magenta", "red", "yellow", "green"]


class AnimatedBanner(Static):
    """Animated ASCII banner that cycles through colors."""
    
    color_index = reactive(0)
    
    def on_mount(self) -> None:
        """Start animation when mounted."""
        self.set_interval(0.5, self.animate_color)
    
    def animate_color(self) -> None:
        """Cycle through colors."""
        self.color_index = (self.color_index + 1) % len(BANNER_COLORS)
        self.update(f"[{BANNER_COLORS[self.color_index]}]{JARVIS_BANNER}[/]")


class LinkCodeGenerator:
    """Utility for generating and parsing link codes."""
    
    @staticmethod
    def generate_link_code(identity: Identity, host: str) -> str:
        """
        Generate a link code containing UID, public key, host, and port.
        Format: jarvis://UID:PUBLIC_KEY_BASE64:HOST:PORT
        """
        public_key_b64 = base64.b64encode(
            identity.keypair.get_public_key_bytes()
        ).decode('utf-8')
        
        link_data = {
            'uid': identity.uid,
            'username': identity.username,
            'public_key': public_key_b64,
            'fingerprint': identity.fingerprint,
            'host': host,
            'port': identity.listen_port
        }
        
        # Encode as base64 for easy sharing
        json_str = json.dumps(link_data)
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return f"jarvis://{encoded}"
    
    @staticmethod
    def parse_link_code(link_code: str) -> Optional[Dict]:
        """
        Parse a link code and return contact information.
        Returns None if invalid.
        """
        try:
            if not link_code.startswith('jarvis://'):
                return None
            
            encoded = link_code[9:]  # Remove 'jarvis://'
            json_str = base64.b64decode(encoded).decode('utf-8')
            data = json.loads(json_str)
            
            # Validate required fields
            required = ['uid', 'username', 'public_key', 'fingerprint', 'host', 'port']
            if not all(field in data for field in required):
                return None
            
            return data
        except Exception:
            return None


class LoadIdentityScreen(ModalScreen):
    """Screen for loading or creating identity."""
    
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]
    
    def __init__(self, identity_manager: IdentityManager, data_dir: str, 
                 default_port: int = 5000):
        super().__init__()
        self.identity_manager = identity_manager
        self.data_dir = data_dir
        self.default_port = default_port
        self.identity: Optional[Identity] = None
        self.password: Optional[str] = None
    
    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        with Container(id="identity-dialog"):
            yield AnimatedBanner()
            yield Label("Welcome to Jarvis", id="welcome-label")
            
            if self.identity_manager.identity_exists():
                yield Label("Enter your password to load identity:", id="prompt-label")
                yield Input(placeholder="Password", password=True, id="password-input")
                yield Horizontal(
                    Button("Load Identity", variant="primary", id="load-btn"),
                    Button("Cancel", variant="default", id="cancel-btn"),
                    id="button-row"
                )
            else:
                yield Label("Create a new identity:", id="prompt-label")
                yield Input(placeholder="Username", id="username-input")
                yield Input(placeholder="Password", password=True, id="password-input")
                yield Input(placeholder="Listen Port", value=str(self.default_port), 
                           id="port-input")
                yield Horizontal(
                    Button("Create Identity", variant="primary", id="create-btn"),
                    Button("Cancel", variant="default", id="cancel-btn"),
                    id="button-row"
                )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "load-btn":
            password_input = self.query_one("#password-input", Input)
            password = password_input.value
            
            identity = self.identity_manager.load_identity(password)
            if identity:
                self.identity = identity
                self.password = password
                self.dismiss((identity, password))
            else:
                password_input.value = ""
                password_input.placeholder = "Incorrect password! Try again..."
        
        elif event.button.id == "create-btn":
            username_input = self.query_one("#username-input", Input)
            password_input = self.query_one("#password-input", Input)
            port_input = self.query_one("#port-input", Input)
            
            username = username_input.value
            password = password_input.value
            try:
                port = int(port_input.value)
            except ValueError:
                port = self.default_port
            
            if username and password:
                identity = self.identity_manager.create_identity(username, password, port)
                self.identity = identity
                self.password = password
                self.dismiss((identity, password))
        
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
    
    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss(None)


class AddContactScreen(ModalScreen):
    """Screen for adding a new contact."""
    
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]
    
    def __init__(self, contact_manager: ContactManager):
        super().__init__()
        self.contact_manager = contact_manager
    
    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        with Container(id="add-contact-dialog"):
            yield Label("Add Contact", id="dialog-title")
            yield Label("Paste Link Code or enter details manually:", id="dialog-subtitle")
            yield Input(placeholder="Link Code (jarvis://...)", id="link-code-input")
            yield Label("Or enter details manually:", id="manual-label")
            yield Input(placeholder="Username", id="username-input")
            yield Input(placeholder="UID (32 hex characters)", id="uid-input")
            yield Input(placeholder="Public Key (base64)", id="pubkey-input")
            yield Input(placeholder="Host (IP or hostname)", id="host-input")
            yield Input(placeholder="Port", value="5000", id="port-input")
            yield Horizontal(
                Button("Add Contact", variant="primary", id="add-btn"),
                Button("Cancel", variant="default", id="cancel-btn"),
                id="button-row"
            )
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "add-btn":
            link_code_input = self.query_one("#link-code-input", Input)
            link_code = link_code_input.value.strip()
            
            if link_code:
                # Try to parse link code
                data = LinkCodeGenerator.parse_link_code(link_code)
                if data:
                    contact = Contact(
                        uid=data['uid'],
                        username=data['username'],
                        public_key=data['public_key'],
                        host=data['host'],
                        port=data['port'],
                        fingerprint=data['fingerprint']
                    )
                    if self.contact_manager.add_contact(contact):
                        self.dismiss(contact)
                    else:
                        link_code_input.placeholder = "Contact already exists!"
                        link_code_input.value = ""
                else:
                    link_code_input.placeholder = "Invalid link code!"
                    link_code_input.value = ""
            else:
                # Manual entry
                username = self.query_one("#username-input", Input).value
                uid = self.query_one("#uid-input", Input).value
                public_key = self.query_one("#pubkey-input", Input).value
                host = self.query_one("#host-input", Input).value
                port_str = self.query_one("#port-input", Input).value
                
                try:
                    port = int(port_str)
                    # Verify and create contact
                    fingerprint = crypto.generate_fingerprint(
                        base64.b64decode(public_key)
                    )
                    contact = Contact(uid, username, public_key, host, port, fingerprint)
                    if self.contact_manager.add_contact(contact):
                        self.dismiss(contact)
                    else:
                        self.query_one("#username-input").placeholder = "Contact exists!"
                except Exception as e:
                    self.query_one("#username-input").placeholder = "Invalid data!"
        
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
    
    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss(None)


class CreateGroupScreen(ModalScreen):
    """Screen for creating a new group."""
    
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]
    
    def __init__(self, group_manager: GroupManager, contact_manager: ContactManager,
                 identity: Identity):
        super().__init__()
        self.group_manager = group_manager
        self.contact_manager = contact_manager
        self.identity = identity
    
    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        with Container(id="create-group-dialog"):
            yield Label("Create Group", id="dialog-title")
            yield Input(placeholder="Group Name", id="group-name-input")
            yield Input(placeholder="Description (optional)", id="group-desc-input")
            yield Label("Select members to invite:", id="members-label")
            yield ListView(id="members-list")
            yield Horizontal(
                Button("Create Group", variant="primary", id="create-btn"),
                Button("Cancel", variant="default", id="cancel-btn"),
                id="button-row"
            )
    
    def on_mount(self) -> None:
        """Populate member list."""
        members_list = self.query_one("#members-list", ListView)
        for contact in self.contact_manager.get_all_contacts():
            members_list.append(ListItem(Label(f"☐ {contact.username}")))
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "create-btn":
            name_input = self.query_one("#group-name-input", Input)
            desc_input = self.query_one("#group-desc-input", Input)
            
            name = name_input.value
            description = desc_input.value
            
            if name:
                # Create group
                group = self.group_manager.create_group(
                    name,
                    self.identity.uid,
                    self.identity.username,
                    base64.b64encode(self.identity.keypair.get_public_key_bytes()).decode('utf-8'),
                    self.identity.fingerprint
                )
                group.description = description
                self.group_manager.save_groups()
                
                self.dismiss(group)
            else:
                name_input.placeholder = "Group name required!"
        
        elif event.button.id == "cancel-btn":
            self.dismiss(None)
    
    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss(None)


class SettingsScreen(ModalScreen):
    """Settings screen."""
    
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]
    
    def __init__(self, identity: Identity):
        super().__init__()
        self.identity = identity
    
    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        with Container(id="settings-dialog"):
            yield Label("Settings", id="dialog-title")
            yield Label(f"Username: {self.identity.username}", id="username-label")
            yield Label(f"UID: {self.identity.uid}", id="uid-label")
            yield Label(f"Fingerprint:", id="fp-label")
            yield Label(format_fingerprint(self.identity.fingerprint), id="fp-value")
            yield Label(f"Listen Port: {self.identity.listen_port}", id="port-label")
            yield Label("", id="spacer")
            yield Label("Link Code (share this to add you as a contact):", id="link-label")
            yield Input(value="", id="link-code-display", disabled=True)
            yield Horizontal(
                Button("Copy Link Code", variant="primary", id="copy-btn"),
                Button("Close", variant="default", id="close-btn"),
                id="button-row"
            )
    
    def on_mount(self) -> None:
        """Generate link code on mount."""
        # Default to localhost, user can change if needed
        link_code = LinkCodeGenerator.generate_link_code(self.identity, "localhost")
        self.query_one("#link-code-display", Input).value = link_code
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "copy-btn":
            import pyperclip
            link_code_input = self.query_one("#link-code-display", Input)
            try:
                pyperclip.copy(link_code_input.value)
                self.query_one("#link-label").update(
                    "Link Code (copied to clipboard!):"
                )
            except Exception:
                pass
        elif event.button.id == "close-btn":
            self.dismiss()
    
    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss()


class ContactList(ListView):
    """List of contacts with status indicators."""
    
    def __init__(self, contact_manager: ContactManager):
        super().__init__()
        self.contact_manager = contact_manager
    
    def refresh_contacts(self) -> None:
        """Refresh the contact list."""
        self.clear()
        contacts = self.contact_manager.get_all_contacts()
        for contact in contacts:
            status_icon = "🟢" if contact.status == "online" else "🔴"
            label = Label(f"{status_icon} {contact.username}")
            self.append(ListItem(label))


class ChatView(ScrollableContainer):
    """Chat message view."""
    
    def __init__(self):
        super().__init__()
        self.messages: List[MessageModel] = []
    
    def display_messages(self, messages: List[MessageModel], 
                        my_uid: str, contact_manager: ContactManager) -> None:
        """Display messages in the chat view."""
        self.remove_children()
        self.messages = messages
        
        for msg in messages:
            timestamp_str = format_timestamp_relative(msg.timestamp)
            
            if msg.is_group_message():
                # Group message - show sender name
                sender_name = "You" if msg.sent_by_me else "Unknown"
                if not msg.sent_by_me and msg.sender_uid:
                    contact = contact_manager.get_contact(msg.sender_uid)
                    if contact:
                        sender_name = contact.username
                
                if msg.sent_by_me:
                    text = f"[cyan]{sender_name}[/] ([dim]{timestamp_str}[/]): {msg.content}"
                else:
                    text = f"[yellow]{sender_name}[/] ([dim]{timestamp_str}[/]): {msg.content}"
            else:
                # Direct message
                if msg.sent_by_me:
                    text = f"[cyan]You[/] ([dim]{timestamp_str}[/]): {msg.content}"
                else:
                    text = f"[yellow]Contact[/] ([dim]{timestamp_str}[/]): {msg.content}"
            
            self.mount(Label(text))
    
    def add_message(self, msg: MessageModel, my_uid: str, 
                   contact_manager: ContactManager) -> None:
        """Add a single message to the view."""
        self.messages.append(msg)
        
        timestamp_str = format_timestamp_relative(msg.timestamp)
        
        if msg.is_group_message():
            sender_name = "You" if msg.sent_by_me else "Unknown"
            if not msg.sent_by_me and msg.sender_uid:
                contact = contact_manager.get_contact(msg.sender_uid)
                if contact:
                    sender_name = contact.username
            
            if msg.sent_by_me:
                text = f"[cyan]{sender_name}[/] ([dim]{timestamp_str}[/]): {msg.content}"
            else:
                text = f"[yellow]{sender_name}[/] ([dim]{timestamp_str}[/]): {msg.content}"
        else:
            if msg.sent_by_me:
                text = f"[cyan]You[/] ([dim]{timestamp_str}[/]): {msg.content}"
            else:
                text = f"[yellow]Contact[/] ([dim]{timestamp_str}[/]): {msg.content}"
        
        self.mount(Label(text))


class JarvisApp(App):
    """Main Jarvis application with Textual UI."""
    
    CSS = """
    #identity-dialog, #add-contact-dialog, #create-group-dialog, #settings-dialog {
        align: center middle;
        width: 80;
        height: auto;
        background: $surface;
        border: solid $primary;
        padding: 1 2;
    }
    
    #welcome-label, #dialog-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    
    #prompt-label, #dialog-subtitle, #manual-label, #members-label, #link-label {
        margin-bottom: 1;
    }
    
    Input {
        margin-bottom: 1;
    }
    
    #button-row {
        align: center middle;
        width: 100%;
        height: auto;
    }
    
    Button {
        margin: 0 1;
    }
    
    #main-container {
        layout: horizontal;
        height: 100%;
    }
    
    #contacts-panel {
        width: 30;
        border-right: solid $primary;
    }
    
    #chat-panel {
        width: 1fr;
    }
    
    #message-input-container {
        height: 3;
        dock: bottom;
    }
    
    #message-input {
        width: 1fr;
    }
    
    ChatView {
        height: 1fr;
        border-bottom: solid $primary;
    }
    
    ContactList {
        height: 1fr;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+c", "add_contact", "Add Contact"),
        Binding("ctrl+g", "create_group", "New Group"),
        Binding("ctrl+s", "settings", "Settings"),
        Binding("ctrl+q", "quit", "Quit"),
    ]
    
    def __init__(self, data_dir: str, default_port: int = 5000, debug: bool = False):
        super().__init__()
        self.data_dir = data_dir
        self.default_port = default_port
        self.debug = debug
        
        self.identity: Optional[Identity] = None
        self.password: Optional[str] = None
        
        # Initialize managers
        self.identity_manager = IdentityManager(os.path.join(data_dir, 'identity.enc'))
        self.contact_manager = ContactManager(os.path.join(data_dir, 'contacts.json'))
        self.message_store = MessageStore(os.path.join(data_dir, 'messages.json'))
        self.group_manager = GroupManager(os.path.join(data_dir, 'groups.json'))
        self.network_manager: Optional[NetworkManager] = None
        
        self.current_contact: Optional[Contact] = None
        self.current_group: Optional[Group] = None
    
    def compose(self) -> ComposeResult:
        """Compose the main application layout."""
        yield Header()
        with Container(id="main-container"):
            with Vertical(id="contacts-panel"):
                yield Label("Contacts & Groups")
                yield ContactList(self.contact_manager)
            with Vertical(id="chat-panel"):
                yield Label("Select a contact or group to start chatting", id="chat-header")
                yield ChatView()
                with Horizontal(id="message-input-container"):
                    yield Input(placeholder="Type a message...", id="message-input")
                    yield Button("Send", variant="primary", id="send-btn")
        yield Footer()
    
    async def on_mount(self) -> None:
        """Initialize the application."""
        # Load or create identity
        result = await self.push_screen_wait(
            LoadIdentityScreen(self.identity_manager, self.data_dir, self.default_port)
        )
        
        if result is None:
            self.exit()
            return
        
        self.identity, self.password = result
        
        # Initialize network manager
        self.network_manager = NetworkManager(
            self.identity.keypair,
            self.identity.uid,
            self.identity.username,
            self.identity.listen_port,
            self.contact_manager
        )
        
        # Set up callbacks
        self.network_manager.on_message_callback = self._handle_incoming_message
        self.network_manager.on_group_message_callback = self._handle_incoming_group_message
        self.network_manager.on_connection_state_callback = self._handle_connection_state_change
        
        # Start network server
        if not self.network_manager.start_server():
            self.notify("Failed to start network server", severity="error")
            self.exit()
            return
        
        # Refresh contact list
        contact_list = self.query_one(ContactList)
        contact_list.refresh_contacts()
        
        self.notify(f"Welcome, {self.identity.username}!", severity="information")
    
    def _handle_incoming_message(self, sender_uid: str, content: str, 
                                 message_id: str, timestamp: str) -> None:
        """Handle incoming direct message."""
        contact = self.contact_manager.get_contact(sender_uid)
        if not contact:
            return
        
        # Store message
        msg = MessageModel(
            contact_uid=sender_uid,
            content=content,
            sent_by_me=False,
            timestamp=timestamp,
            message_id=message_id
        )
        self.message_store.add_message(msg)
        
        # Update UI if viewing this conversation
        if self.current_contact and self.current_contact.uid == sender_uid:
            chat_view = self.query_one(ChatView)
            chat_view.add_message(msg, self.identity.uid, self.contact_manager)
        
        # Show notification
        self.notify(f"New message from {contact.username}", severity="information")
    
    def _handle_incoming_group_message(self, group_id: str, sender_uid: str,
                                      content: str, message_id: str, timestamp: str) -> None:
        """Handle incoming group message."""
        group = self.group_manager.get_group(group_id)
        if not group:
            return
        
        # Store message
        msg = MessageModel(
            contact_uid=group_id,  # Use group_id as contact_uid for storage
            content=content,
            sent_by_me=False,
            timestamp=timestamp,
            message_id=message_id,
            group_id=group_id,
            sender_uid=sender_uid
        )
        self.message_store.add_message(msg)
        
        # Update UI if viewing this group
        if self.current_group and self.current_group.group_id == group_id:
            chat_view = self.query_one(ChatView)
            chat_view.add_message(msg, self.identity.uid, self.contact_manager)
        
        # Show notification
        sender = self.contact_manager.get_contact(sender_uid)
        sender_name = sender.username if sender else "Unknown"
        self.notify(f"New message in {group.name} from {sender_name}", 
                   severity="information")
    
    def _handle_connection_state_change(self, uid: str, state: ConnectionState) -> None:
        """Handle connection state change."""
        contact = self.contact_manager.get_contact(uid)
        if contact:
            if state == ConnectionState.AUTHENTICATED:
                self.contact_manager.mark_online(uid)
            else:
                self.contact_manager.mark_offline(uid)
            
            # Refresh contact list
            contact_list = self.query_one(ContactList)
            contact_list.refresh_contacts()
    
    async def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle contact selection."""
        # Get selected contact
        contacts = self.contact_manager.get_all_contacts()
        if event.list_view.index < len(contacts):
            contact = contacts[event.list_view.index]
            self.current_contact = contact
            self.current_group = None
            
            # Load and display conversation
            messages = self.message_store.get_conversation(contact.uid)
            chat_view = self.query_one(ChatView)
            chat_view.display_messages(messages, self.identity.uid, self.contact_manager)
            
            # Update header
            self.query_one("#chat-header", Label).update(
                f"Chat with {contact.username}"
            )
            
            # Mark as read
            self.message_store.mark_as_read(contact.uid)
            
            # Try to connect if not connected
            if not self.network_manager.is_connected(contact.uid):
                self.run_worker(self._connect_to_contact(contact))
    
    async def _connect_to_contact(self, contact: Contact) -> None:
        """Connect to a contact in the background."""
        if self.network_manager.connect_to_peer(contact):
            self.notify(f"Connected to {contact.username}", severity="information")
        else:
            self.notify(f"Failed to connect to {contact.username}", severity="warning")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle send button press."""
        if event.button.id == "send-btn":
            self._send_current_message()
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle message input submission."""
        if event.input.id == "message-input":
            self._send_current_message()
    
    def _send_current_message(self) -> None:
        """Send the current message."""
        message_input = self.query_one("#message-input", Input)
        content = message_input.value.strip()
        
        if not content:
            return
        
        if self.current_contact:
            # Send direct message
            message_id = crypto.generate_secure_token(16)
            timestamp = datetime.now().isoformat()
            
            if self.network_manager.send_message(
                self.current_contact.uid, content, message_id, timestamp
            ):
                # Store message
                msg = MessageModel(
                    contact_uid=self.current_contact.uid,
                    content=content,
                    sent_by_me=True,
                    timestamp=timestamp,
                    message_id=message_id
                )
                self.message_store.add_message(msg)
                
                # Update UI
                chat_view = self.query_one(ChatView)
                chat_view.add_message(msg, self.identity.uid, self.contact_manager)
                
                message_input.value = ""
            else:
                self.notify("Failed to send message", severity="error")
        
        elif self.current_group:
            # Send group message
            message_id = crypto.generate_secure_token(16)
            timestamp = datetime.now().isoformat()
            
            if self.network_manager.send_group_message(
                self.current_group.group_id, content, message_id, timestamp
            ) > 0:
                # Store message
                msg = MessageModel(
                    contact_uid=self.current_group.group_id,
                    content=content,
                    sent_by_me=True,
                    timestamp=timestamp,
                    message_id=message_id,
                    group_id=self.current_group.group_id,
                    sender_uid=self.identity.uid
                )
                self.message_store.add_message(msg)
                
                # Update UI
                chat_view = self.query_one(ChatView)
                chat_view.add_message(msg, self.identity.uid, self.contact_manager)
                
                message_input.value = ""
            else:
                self.notify("Failed to send group message", severity="error")
    
    async def action_add_contact(self) -> None:
        """Show add contact screen."""
        result = await self.push_screen_wait(AddContactScreen(self.contact_manager))
        if result:
            contact_list = self.query_one(ContactList)
            contact_list.refresh_contacts()
            self.notify(f"Added contact: {result.username}", severity="information")
    
    async def action_create_group(self) -> None:
        """Show create group screen."""
        result = await self.push_screen_wait(
            CreateGroupScreen(self.group_manager, self.contact_manager, self.identity)
        )
        if result:
            self.notify(f"Created group: {result.name}", severity="information")
            # TODO: Add groups to the contact list view
    
    async def action_settings(self) -> None:
        """Show settings screen."""
        await self.push_screen_wait(SettingsScreen(self.identity))
    
    def action_quit(self) -> None:
        """Quit the application."""
        if self.network_manager:
            self.network_manager.disconnect_all()
            self.network_manager.stop_server()
        self.exit()
