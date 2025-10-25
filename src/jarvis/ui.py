"""
Jarvis - Manual terminal user interface.

Created by orpheus497
"""

import os
import sys
import asyncio
import random
import base64
from typing import Optional, List, Dict
from datetime import datetime

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

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "underline": "\033[4m",
    "end": "\033[0m",
}

def colorize(text, color):
    """Colorize text for the terminal."""
    return f"{COLORS.get(color, '')}{text}{COLORS['end']}"

class JarvisUI:
    """Manual terminal UI for Jarvis."""

    def __init__(self, data_dir: str, default_port: int = 5000, debug: bool = False):
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
        
        # Initialize network manager
        self.network_manager = NetworkManager(
            None, # keypair
            None, # uid
            None, # username
            self.default_port,
            self.contact_manager
        )

    def run(self):
        """Run the UI."""
        self._clear_screen()
        print(colorize(JARVIS_BANNER, "cyan"))
        print(colorize("Welcome to Jarvis", "yellow"))

        if not self.identity_manager.identity_exists():
            self._create_identity()
        else:
            self._load_identity()

        if not self.identity:
            return

        self.network_manager.identity = self.identity.keypair
        self.network_manager.my_uid = self.identity.uid
        self.network_manager.my_username = self.identity.username
        self.network_manager.listen_port = self.identity.listen_port

        if not self.network_manager.start_server():
            print(colorize("Failed to start network server.", "red"))
            return

        self._main_loop()

    def _create_identity(self):
        """Create a new identity."""
        print(colorize("Create a new identity", "bold"))
        username = input("Username: ")
        password = input("Password: ")
        self.identity = self.identity_manager.create_identity(username, password, self.default_port)
        self.password = password
        print(colorize("Identity created successfully!", "green"))
        print(f"Username: {self.identity.username}")
        print(f"UID: {self.identity.uid}")
        print(f"Fingerprint: {self.identity.fingerprint}")

    def _load_identity(self):
        """Load an existing identity."""
        print(colorize("Load an existing identity", "bold"))
        password = input("Password: ")
        self.identity = self.identity_manager.load_identity(password)
        if not self.identity:
            print(colorize("Incorrect password.", "red"))
            return
        self.password = password
        print(colorize("Identity loaded successfully!", "green"))

    def _main_loop(self):
        """The main UI loop."""
        while True:
            try:
                command = input(colorize("> ", "green"))
                if command == "help":
                    self._print_help()
                elif command.startswith("send"):
                    self._send_message(command)
                elif command.startswith("add"):
                    self._add_contact(command)
                elif command == "list":
                    self._list_contacts()
                elif command == "exit":
                    break
                else:
                    print(colorize("Unknown command. Type 'help' for a list of commands.", "yellow"))
            except KeyboardInterrupt:
                break

        self.network_manager.disconnect_all()
        self.network_manager.stop_server()
        print(colorize("Jarvis has been shut down.", "yellow"))

    def _print_help(self):
        """Print the help message."""
        print(colorize("Commands:", "bold"))
        print("  send <username> <message>")
        print("  add <username> <uid> <public_key> <host> <port>")
        print("  list")
        print("  exit")

    def _send_message(self, command: str):
        """Send a message to a contact."""
        parts = command.split(" ", 2)
        if len(parts) == 3:
            username, message = parts[1], parts[2]
            contact = self.contact_manager.get_contact_by_username(username)
            if contact:
                self.network_manager.send_message(contact.uid, message, "", "")
            else:
                print(colorize(f"Contact '{username}' not found.", "red"))
        else:
            print(colorize("Usage: send <username> <message>", "yellow"))

    def _add_contact(self, command: str):
        """Add a new contact."""
        parts = command.split(" ")
        if len(parts) == 6:
            username, uid, public_key, host, port = parts[1], parts[2], parts[3], parts[4], parts[5]
            fingerprint = crypto.generate_fingerprint(base64.b64decode(public_key))
            contact = Contact(uid, username, public_key, host, int(port), fingerprint)
            self.contact_manager.add_contact(contact)
            print(colorize(f"Contact '{username}' added.", "green"))
        else:
            print(colorize("Usage: add <username> <uid> <public_key> <host> <port>", "yellow"))

    def _list_contacts(self):
        """List all contacts."""
        print(colorize("Contacts:", "bold"))
        for contact in self.contact_manager.get_all_contacts():
            print(f"- {contact.username}")

    def _clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

class JarvisApp(App):
    """Main Jarvis application."""

    def __init__(self, data_dir: str, default_port: int = 5000, debug: bool = False):
        super().__init__()
        self.ui = JarvisUI(data_dir, default_port, debug)

    def on_mount(self) -> None:
        """Called when app is mounted."""
        self.ui.run()
        self.exit()
