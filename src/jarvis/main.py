"""
Jarvis - Main entry point for the application.

Created by orpheus497
"""

import sys
import os
import argparse
from pathlib import Path

from . import __version__
from .ui import JarvisApp
from .daemon_manager import DaemonManager


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
        '--ipc-port',
        type=int,
        default=5999,
        help='Port for IPC communication with server (default: 5999)'
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
    
    # Create daemon manager
    daemon_manager = DaemonManager(data_dir, args.ipc_port)
    
    # Check if server is running
    if not daemon_manager.is_running():
        print("Starting Jarvis server...")
        if not daemon_manager.start_daemon(timeout=10):
            print("Failed to start server. Exiting.")
            print("\nTroubleshooting:")
            print(f"  - Check if port {args.ipc_port} is available")
            print(f"  - Check logs in: {data_dir}")
            print(f"  - Try: python -m jarvis.server --data-dir {data_dir}")
            sys.exit(1)
        print("Server started successfully.")
    else:
        pid = daemon_manager.get_pid()
        print(f"Server already running (PID: {pid}).")
    
    # Run the Textual UI application (client)
    app = JarvisApp(str(data_dir), args.port, args.ipc_port, args.debug)
    app.run()


if __name__ == '__main__':
    main()