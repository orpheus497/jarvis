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

# Color sequence for animated banner - black, red, grey, white, dark purple
BANNER_COLORS = ["white", "red", "bright_white", "#8b0000", "#4b0082", "grey50"]


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

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input fields."""
        if self.identity_manager.identity_exists():
            # Load identity flow - only password input
            if event.input.id == "password-input":
                # Trigger load button
                password = event.input.value
                identity = self.identity_manager.load_identity(password)
                if identity:
                    self.identity = identity
                    self.password = password
                    self.dismiss((identity, password))
                else:
                    event.input.value = ""
                    event.input.placeholder = "Incorrect password! Try again..."
        else:
            # Create identity flow - progress through fields
            if event.input.id == "username-input":
                # Move to password input
                password_input = self.query_one("#password-input", Input)
                password_input.focus()
            elif event.input.id == "password-input":
                # Move to port input
                port_input = self.query_one("#port-input", Input)
                port_input.focus()
            elif event.input.id == "port-input":
                # Submit the form
                username_input = self.query_one("#username-input", Input)
                password_input = self.query_one("#password-input", Input)
                
                username = username_input.value
                password = password_input.value
                try:
                    port = int(event.input.value)
                except ValueError:
                    port = self.default_port
                
                if username and password:
                    identity = self.identity_manager.create_identity(username, password, port)
                    self.identity = identity
                    self.password = password
                    self.dismiss((identity, password))

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
            yield Button("Paste from Clipboard", variant="default", id="paste-btn")
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
        if event.button.id == "paste-btn":
            import pyperclip
            try:
                clipboard_text = pyperclip.paste()
                link_code_input = self.query_one("#link-code-input", Input)
                link_code_input.value = clipboard_text.strip()
            except Exception:
                pass
        elif event.button.id == "add-btn":
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

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input fields."""
        # Trigger add button when Enter is pressed on any input
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


class LockScreen(ModalScreen):
    """Lock screen to secure the application."""

    BINDINGS = [
        Binding("escape", "dismiss_lock", "Cancel"),
    ]

    def __init__(self, password: str):
        super().__init__()
        self.password = password
        self.attempts = 0

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        with Container(id="lock-dialog"):
            yield AnimatedBanner()
            yield Label("Jarvis is Locked", id="lock-title")
            yield Label("Enter your password to unlock:", id="lock-prompt")
            yield Input(placeholder="Password", password=True, id="password-input")
            yield Horizontal(
                Button("Unlock", variant="primary", id="unlock-btn"),
                Button("Cancel", variant="default", id="cancel-btn"),
                id="button-row"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "unlock-btn":
            password_input = self.query_one("#password-input", Input)
            entered_password = password_input.value

            if entered_password == self.password:
                self.dismiss(True)
            else:
                self.attempts += 1
                password_input.value = ""
                password_input.placeholder = f"Incorrect password! (Attempt {self.attempts})"
        elif event.button.id == "cancel-btn":
            self.dismiss(False)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in password input."""
        if event.input.id == "password-input":
            entered_password = event.input.value

            if entered_password == self.password:
                self.dismiss(True)
            else:
                self.attempts += 1
                event.input.value = ""
                event.input.placeholder = f"Incorrect password! (Attempt {self.attempts})"

    def action_dismiss_lock(self) -> None:
        """Cancel lock (do not unlock)."""
        self.dismiss(False)


class DeleteAccountScreen(ModalScreen):
    """Screen for deleting account with confirmation."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, identity: Identity, password: str):
        super().__init__()
        self.identity = identity
        self.stored_password = password

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        with Container(id="delete-account-dialog"):
            yield Label("Delete Account", id="dialog-title")
            yield Label("⚠️  WARNING: This action cannot be undone!", id="warning-label")
            yield Label("", id="spacer")
            yield Label("This will permanently delete:", id="info-label")
            yield Label("  • Your identity and keys", id="info-detail-1")
            yield Label("  • All contacts", id="info-detail-2")
            yield Label("  • All messages", id="info-detail-3")
            yield Label("  • All groups", id="info-detail-4")
            yield Label("", id="spacer2")
            yield Label("Enter your password to confirm deletion:", id="confirm-label")
            yield Input(placeholder="Password", password=True, id="password-input")
            yield Horizontal(
                Button("Delete Account", variant="error", id="delete-btn"),
                Button("Cancel", variant="default", id="cancel-btn"),
                id="button-row"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "delete-btn":
            password_input = self.query_one("#password-input", Input)
            entered_password = password_input.value

            if entered_password == self.stored_password:
                self.dismiss(True)
            else:
                password_input.value = ""
                password_input.placeholder = "Incorrect password!"
        elif event.button.id == "cancel-btn":
            self.dismiss(False)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in password input."""
        if event.input.id == "password-input":
            entered_password = event.input.value

            if entered_password == self.stored_password:
                self.dismiss(True)
            else:
                event.input.value = ""
                event.input.placeholder = "Incorrect password!"

    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss(False)


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
            yield Label(f"UID:", id="uid-label")
            yield Input(value=self.identity.uid, id="uid-display", disabled=True)
            yield Button("Copy UID", variant="default", id="copy-uid-btn")
            yield Label(f"Fingerprint:", id="fp-label")
            yield Input(value=format_fingerprint(self.identity.fingerprint), 
                       id="fp-display", disabled=True)
            yield Button("Copy Fingerprint", variant="default", id="copy-fp-btn")
            yield Label(f"Listen Port: {self.identity.listen_port}", id="port-label")
            yield Label("", id="spacer")
            yield Label("Link Code (share this to add you as a contact):", id="link-label")
            yield Input(value="", id="link-code-display", disabled=True)
            yield Horizontal(
                Button("Copy Link Code", variant="primary", id="copy-btn"),
                Button("Delete Account", variant="error", id="delete-account-btn"),
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
        import pyperclip
        
        if event.button.id == "copy-btn":
            link_code_input = self.query_one("#link-code-display", Input)
            try:
                pyperclip.copy(link_code_input.value)
                self.query_one("#link-label").update(
                    "Link Code (copied to clipboard!):"
                )
            except Exception:
                pass
        elif event.button.id == "copy-uid-btn":
            try:
                pyperclip.copy(self.identity.uid)
                self.query_one("#uid-label").update("UID: (copied!)")
            except Exception:
                pass
        elif event.button.id == "copy-fp-btn":
            try:
                pyperclip.copy(self.identity.fingerprint)
                self.query_one("#fp-label").update("Fingerprint: (copied!)")
            except Exception:
                pass
        elif event.button.id == "delete-account-btn":
            self.dismiss("delete_account")
        elif event.button.id == "close-btn":
            self.dismiss(None)

    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss(None)


class ContactDetailsScreen(ModalScreen):
    """Screen showing contact details with management options."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, contact: Contact, contact_manager: ContactManager, 
                 message_store: MessageStore):
        super().__init__()
        self.contact = contact
        self.contact_manager = contact_manager
        self.message_store = message_store

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        with Container(id="contact-details-dialog"):
            yield Label("Contact Details", id="dialog-title")
            yield Label(f"Username: {self.contact.username}", id="contact-username")
            yield Label(f"UID:", id="uid-label")
            yield Input(value=self.contact.uid, id="uid-display", disabled=True)
            yield Label(f"Fingerprint:", id="fp-label")
            yield Input(value=format_fingerprint(self.contact.fingerprint), 
                       id="fp-display", disabled=True)
            yield Label(f"Host: {self.contact.host}:{self.contact.port}", id="host-label")
            yield Label(f"Status: {self.contact.status}", id="status-label")
            yield Label(f"Verified: {'Yes' if self.contact.verified else 'No'}", 
                       id="verified-label")
            yield Label("", id="spacer")
            yield Horizontal(
                Button("Copy UID", variant="primary", id="copy-uid-btn"),
                Button("Copy Fingerprint", variant="primary", id="copy-fp-btn"),
                Button("Delete Contact", variant="error", id="delete-contact-btn"),
                Button("Close", variant="default", id="close-btn"),
                id="button-row"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        import pyperclip
        
        if event.button.id == "copy-uid-btn":
            try:
                pyperclip.copy(self.contact.uid)
                self.query_one("#uid-label").update("UID: (copied!)")
            except Exception:
                pass
        elif event.button.id == "copy-fp-btn":
            try:
                pyperclip.copy(self.contact.fingerprint)
                self.query_one("#fp-label").update("Fingerprint: (copied!)")
            except Exception:
                pass
        elif event.button.id == "delete-contact-btn":
            self.dismiss("delete")
        elif event.button.id == "close-btn":
            self.dismiss(None)

    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss(None)


class GroupDetailsScreen(ModalScreen):
    """Screen showing group details with management options."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, group: Group, group_manager: GroupManager, 
                 message_store: MessageStore):
        super().__init__()
        self.group = group
        self.group_manager = group_manager
        self.message_store = message_store

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        with Container(id="group-details-dialog"):
            yield Label("Group Details", id="dialog-title")
            yield Label(f"Name: {self.group.name}", id="group-name")
            yield Label(f"Group ID:", id="gid-label")
            yield Input(value=self.group.group_id, id="gid-display", disabled=True)
            yield Label(f"Description: {self.group.description or 'None'}", 
                       id="desc-label")
            yield Label(f"Members: {len(self.group.members)}", id="members-label")
            yield Label(f"Created: {self.group.created_at[:10]}", id="created-label")
            yield Label("", id="spacer")
            yield Horizontal(
                Button("Copy Group ID", variant="primary", id="copy-gid-btn"),
                Button("Delete Group", variant="error", id="delete-group-btn"),
                Button("Close", variant="default", id="close-btn"),
                id="button-row"
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        import pyperclip
        
        if event.button.id == "copy-gid-btn":
            try:
                pyperclip.copy(self.group.group_id)
                self.query_one("#gid-label").update("Group ID: (copied!)")
            except Exception:
                pass
        elif event.button.id == "delete-group-btn":
            self.dismiss("delete")
        elif event.button.id == "close-btn":
            self.dismiss(None)

    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss(None)


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
    Screen {
        background: #000000;
    }

    #identity-dialog, #add-contact-dialog, #create-group-dialog, #settings-dialog, 
    #lock-dialog, #delete-account-dialog, #contact-details-dialog, #group-details-dialog {
        align: center middle;
        width: 80;
        height: auto;
        background: #1a1a1a;
        border: solid #8b0000;
        padding: 1 2;
    }

    #welcome-label, #dialog-title, #lock-title {
        text-align: center;
        text-style: bold;
        color: #ff4444;
        margin-bottom: 1;
    }
    
    #warning-label {
        text-align: center;
        text-style: bold;
        color: #ff0000;
        margin-bottom: 1;
    }
    
    #lock-prompt, #confirm-label, #info-label {
        color: #cccccc;
        margin-bottom: 1;
    }
    
    #info-detail-1, #info-detail-2, #info-detail-3, #info-detail-4 {
        color: #888888;
        margin-left: 2;
    }

    #prompt-label, #dialog-subtitle, #manual-label, #members-label, #link-label {
        margin-bottom: 1;
        color: #cccccc;
    }

    Label {
        color: #cccccc;
    }

    Input {
        margin-bottom: 1;
        background: #0a0a0a;
        border: solid #444444;
        color: #ffffff;
    }

    Input:focus {
        border: solid #8b0000;
    }

    #button-row {
        align: center middle;
        width: 100%;
        height: auto;
    }

    Button {
        margin: 0 1;
        background: #2a0a0a;
        color: #ff4444;
        border: solid #8b0000;
    }

    Button:hover {
        background: #8b0000;
        color: #ffffff;
    }

    Button.-primary {
        background: #8b0000;
        color: #ffffff;
    }

    Button.-primary:hover {
        background: #cc0000;
    }

    #main-container {
        layout: horizontal;
        height: 100%;
        background: #000000;
    }

    #contacts-panel {
        width: 30;
        border-right: solid #8b0000;
        background: #0a0a0a;
    }

    #chat-panel {
        width: 1fr;
        background: #000000;
    }

    #message-input-container {
        height: 3;
        dock: bottom;
        background: #0a0a0a;
    }

    #message-input {
        width: 1fr;
    }

    ChatView {
        height: 1fr;
        border-bottom: solid #8b0000;
        background: #000000;
    }

    ContactList {
        height: 1fr;
        background: #0a0a0a;
    }

    Header {
        background: #1a1a1a;
        color: #ff4444;
    }

    Footer {
        background: #1a1a1a;
        color: #cccccc;
    }

    #chat-header {
        color: #ff4444;
        background: #1a1a1a;
        padding: 1;
    }

    #username-label, #uid-label, #fp-label, #fp-value, #port-label, #spacer {
        color: #cccccc;
    }

    #link-code-display {
        background: #0a0a0a;
        color: #666666;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "add_contact", "Add Contact"),
        Binding("ctrl+g", "create_group", "New Group"),
        Binding("ctrl+s", "settings", "Settings"),
        Binding("ctrl+l", "lock_app", "Lock"),
        Binding("ctrl+i", "contact_info", "Contact Info"),
        Binding("ctrl+d", "delete_current", "Delete"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, data_dir: str, default_port: int = 5000, debug: bool = False):
        super().__init__()
        self.data_dir = data_dir
        self.default_port = default_port

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

    def on_mount(self) -> None:
        """Initialize the application."""
        self.run_worker(self.load_identity_worker)

    async def load_identity_worker(self) -> None:
        """Worker to load or create identity."""
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

    def action_add_contact(self) -> None:
        """Show add contact screen."""
        self.run_worker(self._show_add_contact())

    async def _show_add_contact(self) -> None:
        """Worker to show add contact screen."""
        result = await self.push_screen_wait(AddContactScreen(self.contact_manager))
        if result:
            contact_list = self.query_one(ContactList)
            contact_list.refresh_contacts()
            self.notify(f"Added contact: {result.username}", severity="information")

    def action_create_group(self) -> None:
        """Show create group screen."""
        self.run_worker(self._show_create_group())

    async def _show_create_group(self) -> None:
        """Worker to show create group screen."""
        result = await self.push_screen_wait(
            CreateGroupScreen(self.group_manager, self.contact_manager, self.identity)
        )
        if result:
            self.notify(f"Created group: {result.name}", severity="information")
            contact_list = self.query_one(ContactList)
            contact_list.refresh_contacts()

    def action_settings(self) -> None:
        """Show settings screen."""
        self.run_worker(self._show_settings())

    async def _show_settings(self) -> None:
        """Worker to show settings screen."""
        result = await self.push_screen_wait(SettingsScreen(self.identity))
        
        if result == "delete_account":
            # Show delete account confirmation
            delete_result = await self.push_screen_wait(
                DeleteAccountScreen(self.identity, self.password)
            )
            
            if delete_result:
                # Delete all data
                self.identity_manager.delete_identity(self.password)
                self.contact_manager.delete_all_contacts()
                self.message_store.delete_all_messages()
                self.group_manager.delete_all_groups()
                
                # Disconnect and shutdown
                if self.network_manager:
                    self.network_manager.disconnect_all()
                    self.network_manager.stop_server()
                
                self.notify("Account deleted successfully.", severity="warning")
                self.exit()
    
    def action_lock_app(self) -> None:
        """Lock the application."""
        self.run_worker(self._lock_app())
    
    async def _lock_app(self) -> None:
        """Worker to lock the application."""
        result = await self.push_screen_wait(LockScreen(self.password))
        
        if result:
            self.notify("Application unlocked", severity="information")
        else:
            # User cancelled - could optionally do something here
            pass
    
    def action_contact_info(self) -> None:
        """Show info for current contact or group."""
        self.run_worker(self._show_contact_info())
    
    async def _show_contact_info(self) -> None:
        """Worker to show contact or group info."""
        if self.current_contact:
            result = await self.push_screen_wait(
                ContactDetailsScreen(self.current_contact, self.contact_manager, 
                                   self.message_store)
            )
            
            if result == "delete":
                # Confirm and delete contact
                if self.contact_manager.remove_contact(self.current_contact.uid):
                    # Delete conversation
                    self.message_store.delete_conversation(self.current_contact.uid)
                    
                    # Disconnect if connected
                    if self.network_manager:
                        self.network_manager.disconnect_from_peer(self.current_contact.uid)
                    
                    # Clear current selection
                    self.current_contact = None
                    
                    # Refresh UI
                    contact_list = self.query_one(ContactList)
                    contact_list.refresh_contacts()
                    
                    self.query_one("#chat-header", Label).update(
                        "Select a contact or group to start chatting"
                    )
                    chat_view = self.query_one(ChatView)
                    chat_view.display_messages([], self.identity.uid, self.contact_manager)
                    
                    self.notify("Contact deleted successfully", severity="information")
        
        elif self.current_group:
            result = await self.push_screen_wait(
                GroupDetailsScreen(self.current_group, self.group_manager, 
                                 self.message_store)
            )
            
            if result == "delete":
                # Confirm and delete group
                if self.group_manager.delete_group(self.current_group.group_id):
                    # Delete conversation
                    self.message_store.delete_group_conversation(self.current_group.group_id)
                    
                    # Clear current selection
                    self.current_group = None
                    
                    # Refresh UI
                    contact_list = self.query_one(ContactList)
                    contact_list.refresh_contacts()
                    
                    self.query_one("#chat-header", Label).update(
                        "Select a contact or group to start chatting"
                    )
                    chat_view = self.query_one(ChatView)
                    chat_view.display_messages([], self.identity.uid, self.contact_manager)
                    
                    self.notify("Group deleted successfully", severity="information")
        else:
            self.notify("No contact or group selected", severity="warning")
    
    def action_delete_current(self) -> None:
        """Delete current contact or group."""
        # Just call the contact info action which has delete option
        self.action_contact_info()

    def action_quit(self) -> None:
        """Quit the application."""
        if self.network_manager:
            self.network_manager.disconnect_all()
            self.network_manager.stop_server()
        self.exit()