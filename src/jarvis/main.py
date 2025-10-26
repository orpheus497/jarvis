"""
Jarvis - Main entry point for the application.

Created by orpheus497
"""

import sys
import os
import subprocess
import time
import argparse
from pathlib import Path

from . import __version__
from .ui import JarvisApp


def is_server_running(data_dir: Path) -> bool:
    """Check if server is already running."""
    pid_file = data_dir / 'server.pid'
    
    if not pid_file.exists():
        return False
    
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
        
        # Check if process exists
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            # Process doesn't exist, remove stale PID file
            pid_file.unlink()
            return False
    except:
        return False


def start_server(data_dir: Path, ipc_port: int = 5999) -> bool:
    """Start server process in background."""
    try:
        # Start server as detached process
        if sys.platform == 'win32':
            # Windows: use CREATE_NO_WINDOW and DETACHED_PROCESS
            CREATE_NO_WINDOW = 0x08000000
            DETACHED_PROCESS = 0x00000008
            
            subprocess.Popen(
                [sys.executable, '-m', 'jarvis.server', 
                 '--data-dir', str(data_dir),
                 '--ipc-port', str(ipc_port)],
                creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            # Unix: use nohup and redirect output
            subprocess.Popen(
                [sys.executable, '-m', 'jarvis.server',
                 '--data-dir', str(data_dir),
                 '--ipc-port', str(ipc_port)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
        
        # Wait a moment for server to start
        max_wait = 5
        for i in range(max_wait * 10):
            time.sleep(0.1)
            if is_server_running(data_dir):
                return True
        
        return False
    
    except Exception as e:
        print(f"Failed to start server: {e}")
        return False


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
    
    # Check if server is running, start if not
    if not is_server_running(data_dir):
        print("Starting Jarvis server...")
        if not start_server(data_dir, args.ipc_port):
            print("Failed to start server. Exiting.")
            sys.exit(1)
        print("Server started successfully.")
    else:
        print("Server already running.")
    
    # Run the Textual UI application (client)
    app = JarvisApp(str(data_dir), args.port, args.ipc_port, args.debug)
    app.run()

if __name__ == '__main__':
    main()