"""
Jarvis - Main entry point for the application.

Created by orpheus497
"""

import sys
import os
import argparse
from pathlib import Path

from . import __version__
from .identity import IdentityManager
from .contact import ContactManager
from .message import MessageStore
from .group import GroupManager
from .network import NetworkManager


def main():
    """Main entry point for Jarvis application."""
    parser = argparse.ArgumentParser(
        description='Jarvis - Peer-to-peer encrypted messenger',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  jarvis                    # Start Jarvis with default data directory
  jarvis --data-dir ~/jarvis # Use custom data directory
  jarvis --port 5000        # Use custom listen port

Created by orpheus497
        """
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'Jarvis {__version__}'
    )
    
    parser.add_argument(
        '--data-dir',
        type=str,
        default=None,
        help='Data directory for storing identity, contacts, and messages'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Default listen port for P2P connections (default: 5000)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    args = parser.parse_args()
    
    # Determine data directory
    if args.data_dir:
        data_dir = Path(args.data_dir).expanduser().resolve()
    else:
        # Use platform-specific default data directory
        if sys.platform == 'win32':
            data_dir = Path(os.getenv('APPDATA', '~')) / 'Jarvis'
        elif sys.platform == 'darwin':
            data_dir = Path.home() / 'Library' / 'Application Support' / 'Jarvis'
        else:
            data_dir = Path.home() / '.jarvis'
        
        data_dir = data_dir.expanduser().resolve()
    
    # Create data directory if it doesn't exist
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize managers
    identity_manager = IdentityManager(os.path.join(data_dir, 'identity.enc'))
    contact_manager = ContactManager(os.path.join(data_dir, 'contacts.json'))
    message_store = MessageStore(os.path.join(data_dir, 'messages.json'))
    group_manager = GroupManager(os.path.join(data_dir, 'groups.json'))
    
    # Check if identity exists
    if not identity_manager.identity_exists():
        print("No identity found. Please create one.")
        username = input("Enter username: ")
        password = input("Enter password: ")
        identity = identity_manager.create_identity(username, password, args.port)
        print(f"Identity created for {username}.")
        print(f"UID: {identity.uid}")
        print(f"Fingerprint: {identity.fingerprint}")
    else:
        password = input("Enter password to load identity: ")
        identity = identity_manager.load_identity(password)
        if not identity:
            print("Incorrect password.")
            sys.exit(1)
        print(f"Identity loaded for {identity.username}.")
    
    # Initialize network manager
    network_manager = NetworkManager(
        identity.keypair,
        identity.uid,
        identity.username,
        identity.listen_port,
        contact_manager
    )
    
    # Start network server
    if not network_manager.start_server():
        print("Failed to start network server.")
        sys.exit(1)
    
    print("Jarvis is running.")
    print("Type 'help' for a list of commands.")
    
    while True:
        try:
            command = input("> ")
            if command == "help":
                print("Commands:")
                print("  send <username> <message>")
                print("  add <username> <uid> <public_key> <host> <port>")
                print("  list")
                print("  exit")
            elif command.startswith("send"):
                parts = command.split(" ", 2)
                if len(parts) == 3:
                    username, message = parts[1], parts[2]
                    contact = contact_manager.get_contact_by_username(username)
                    if contact:
                        network_manager.send_message(contact.uid, message, "", "")
                    else:
                        print(f"Contact '{username}' not found.")
                else:
                    print("Usage: send <username> <message>")
            elif command.startswith("add"):
                parts = command.split(" ")
                if len(parts) == 6:
                    username, uid, public_key, host, port = parts[1], parts[2], parts[3], parts[4], parts[5]
                    contact = Contact(uid, username, public_key, host, int(port), "")
                    contact_manager.add_contact(contact)
                    print(f"Contact '{username}' added.")
                else:
                    print("Usage: add <username> <uid> <public_key> <host> <port>")
            elif command == "list":
                for contact in contact_manager.get_all_contacts():
                    print(f"- {contact.username}")
            elif command == "exit":
                break
        except KeyboardInterrupt:
            break

    network_manager.disconnect_all()
    network_manager.stop_server()
    print("Jarvis has been shut down.")

if __name__ == '__main__':
    main()