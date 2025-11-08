"""
Jarvis - Daemon Manager for server lifecycle management.

Created by orpheus497

This module manages the Jarvis server daemon lifecycle independently of the UI.
It provides reliable server detection, startup, shutdown, and health monitoring.
"""

import builtins
import contextlib
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class DaemonManager:
    """
    Manages the Jarvis server daemon lifecycle.

    Provides reliable server detection using both PID file and port checking,
    handles daemon startup and shutdown, and monitors daemon health.
    """

    def __init__(self, data_dir: Path, ipc_port: int = 5999):
        """
        Initialize daemon manager.

        Args:
            data_dir: Directory where server stores data and PID file
            ipc_port: Port for IPC communication with server
        """
        if isinstance(data_dir, str):
            data_dir = Path(data_dir)

        self.data_dir = data_dir
        self.ipc_port = ipc_port
        self.pid_file = data_dir / "server.pid"

        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def is_running(self) -> bool:
        """
        Check if server daemon is running.

        Uses both PID file check and port check for reliability.
        Cleans up stale PID files automatically.

        Returns:
            True if server is running, False otherwise
        """
        # Check 1: PID file exists
        if not self.pid_file.exists():
            logger.debug("PID file does not exist")
            return False

        # Check 2: Read PID and verify process exists
        try:
            with open(self.pid_file) as f:
                pid_str = f.read().strip()
                if not pid_str:
                    logger.warning("PID file is empty")
                    self._cleanup_pid_file()
                    return False

                pid = int(pid_str)
        except (OSError, ValueError) as e:
            logger.warning(f"Failed to read PID file: {e}")
            self._cleanup_pid_file()
            return False

        # Check 3: Verify process exists
        if not self._is_process_running(pid):
            logger.warning(f"Process {pid} from PID file is not running")
            self._cleanup_pid_file()
            return False

        # Check 4: Verify port is bound (confirms it's our server)
        if not self._is_port_bound(self.ipc_port):
            logger.warning(f"IPC port {self.ipc_port} is not bound")
            return False

        logger.debug(f"Server daemon is running (PID: {pid}, Port: {self.ipc_port})")
        return True

    def get_pid(self) -> Optional[int]:
        """
        Get the PID of the running server daemon.

        Returns:
            PID if server is running, None otherwise
        """
        if not self.is_running():
            return None

        try:
            with open(self.pid_file) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def start_daemon(self, timeout: int = 10) -> bool:
        """
        Start the server daemon as a detached background process.

        Args:
            timeout: Maximum seconds to wait for startup

        Returns:
            True if server started successfully, False otherwise
        """
        # Check if already running
        if self.is_running():
            logger.info("Server daemon already running")
            return True

        logger.info("Starting server daemon...")

        try:
            # Construct command to start server
            cmd = [
                sys.executable,
                "-m",
                "jarvis.server",
                "--data-dir",
                str(self.data_dir),
                "--ipc-port",
                str(self.ipc_port),
            ]

            # Platform-specific process creation
            if sys.platform == "win32":
                # Windows: use CREATE_NO_WINDOW and DETACHED_PROCESS
                CREATE_NO_WINDOW = 0x08000000
                DETACHED_PROCESS = 0x00000008

                process = subprocess.Popen(
                    cmd,
                    creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=str(self.data_dir),
                )
            else:
                # Unix: use start_new_session for true daemon
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    cwd=str(self.data_dir),
                )

            logger.info(f"Server process launched (PID: {process.pid})")

            # Wait for server to be ready
            if self.wait_for_ready(timeout=timeout):
                logger.info("Server daemon started successfully")
                return True
            else:
                logger.error(f"Server failed to start within {timeout} seconds")
                return False

        except Exception as e:
            logger.error(f"Failed to start server daemon: {e}", exc_info=True)
            return False

    def stop_daemon(self, timeout: int = 10) -> bool:
        """
        Stop the server daemon gracefully.

        Attempts graceful shutdown via signal, falls back to force kill if needed.

        Args:
            timeout: Maximum seconds to wait for shutdown

        Returns:
            True if server stopped, False otherwise
        """
        pid = self.get_pid()
        if pid is None:
            logger.info("Server daemon is not running")
            return True

        logger.info(f"Stopping server daemon (PID: {pid})...")

        try:
            # Send SIGTERM for graceful shutdown
            if sys.platform == "win32":
                # Windows doesn't have SIGTERM, use CTRL_C_EVENT or taskkill
                try:
                    os.kill(pid, signal.CTRL_C_EVENT)
                except AttributeError:
                    # If CTRL_C_EVENT not available, use taskkill
                    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
            else:
                os.kill(pid, signal.SIGTERM)

            # Wait for process to exit
            start_time = time.time()
            while time.time() - start_time < timeout:
                if not self._is_process_running(pid):
                    logger.info("Server daemon stopped gracefully")
                    self._cleanup_pid_file()
                    return True
                time.sleep(0.2)

            # If still running, force kill
            logger.warning("Server did not stop gracefully, forcing shutdown...")
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
            else:
                os.kill(pid, signal.SIGKILL)

            time.sleep(0.5)
            self._cleanup_pid_file()
            logger.info("Server daemon force stopped")
            return True

        except Exception as e:
            logger.error(f"Failed to stop server daemon: {e}", exc_info=True)
            return False

    def restart_daemon(self, timeout: int = 10) -> bool:
        """
        Restart the server daemon.

        Args:
            timeout: Maximum seconds to wait for stop and start

        Returns:
            True if restart successful, False otherwise
        """
        logger.info("Restarting server daemon...")

        # Stop existing daemon
        if not self.stop_daemon(timeout=timeout // 2):
            logger.error("Failed to stop daemon for restart")
            return False

        # Short delay to ensure clean shutdown
        time.sleep(0.5)

        # Start daemon
        if not self.start_daemon(timeout=timeout // 2):
            logger.error("Failed to start daemon after restart")
            return False

        logger.info("Server daemon restarted successfully")
        return True

    def wait_for_ready(self, timeout: int = 10) -> bool:
        """
        Wait for server daemon to be ready for connections.

        Polls for server readiness by checking if running and IPC port is bound.

        Args:
            timeout: Maximum seconds to wait

        Returns:
            True if server ready, False if timeout
        """
        logger.debug(f"Waiting for server to be ready (timeout: {timeout}s)...")

        start_time = time.time()
        last_log = 0

        while time.time() - start_time < timeout:
            # Check if server is running and port is bound
            if self.is_running() and self._is_port_bound(self.ipc_port):
                # Try connecting to verify server is accepting connections
                if self._can_connect(self.ipc_port):
                    logger.debug("Server is ready")
                    return True

            # Log progress every 2 seconds
            elapsed = time.time() - start_time
            if elapsed - last_log >= 2:
                logger.debug(f"Waiting for server... ({elapsed:.1f}s)")
                last_log = elapsed

            time.sleep(0.2)

        logger.warning(f"Server not ready after {timeout} seconds")
        return False

    def get_status(self) -> dict:
        """
        Get server daemon status information.

        Returns:
            Dictionary with status information:
            - running: bool
            - pid: int or None
            - port: int
            - port_bound: bool
            - connectable: bool
        """
        running = self.is_running()
        pid = self.get_pid() if running else None
        port_bound = self._is_port_bound(self.ipc_port)
        connectable = self._can_connect(self.ipc_port) if port_bound else False

        return {
            "running": running,
            "pid": pid,
            "port": self.ipc_port,
            "port_bound": port_bound,
            "connectable": connectable,
        }

    def _is_process_running(self, pid: int) -> bool:
        """
        Check if a process with given PID is running.

        Args:
            pid: Process ID to check

        Returns:
            True if process exists, False otherwise
        """
        try:
            # Send signal 0 to check if process exists (doesn't actually send signal)
            os.kill(pid, 0)
            return True
        except OSError:
            return False
        except Exception as e:
            logger.debug(f"Error checking process {pid}: {e}")
            return False

    def _is_port_bound(self, port: int) -> bool:
        """
        Check if a port is bound (in use).

        Args:
            port: Port number to check

        Returns:
            True if port is bound, False otherwise
        """
        try:
            # Try to bind to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)

            try:
                sock.bind(("127.0.0.1", port))
                # If bind succeeds, port is NOT in use
                sock.close()
                return False
            except OSError:
                # If bind fails, port IS in use
                return True
        except Exception as e:
            logger.debug(f"Error checking port {port}: {e}")
            return False
        finally:
            with contextlib.suppress(builtins.BaseException):
                sock.close()

    def _can_connect(self, port: int, timeout: float = 1.0) -> bool:
        """
        Check if we can connect to a port.

        Args:
            port: Port number to connect to
            timeout: Connection timeout in seconds

        Returns:
            True if connection successful, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            try:
                sock.connect(("127.0.0.1", port))
                sock.close()
                return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                return False
        except Exception as e:
            logger.debug(f"Error connecting to port {port}: {e}")
            return False
        finally:
            with contextlib.suppress(builtins.BaseException):
                sock.close()

    def _cleanup_pid_file(self):
        """Remove stale PID file."""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
                logger.debug("Removed stale PID file")
        except Exception as e:
            logger.warning(f"Failed to remove PID file: {e}")
