"""
Jarvis - Connection State Machine for reliable connection management.

Created by orpheus497

This module implements a formal finite state machine for P2P connection lifecycle.
Provides proper state transitions, validation, and event handling for robust connections.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, Optional

from .constants import (
    STATE_AUTHENTICATING_TIMEOUT,
    STATE_CONNECTING_TIMEOUT,
    STATE_RECONNECTING_DELAY,
    STATE_TRANSITION_TIMEOUT,
)

logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Connection states for P2P connections."""

    DISCONNECTED = auto()  # Not connected
    DISCOVERING = auto()  # Discovering peer address
    CONNECTING = auto()  # Establishing TCP connection
    AUTHENTICATING = auto()  # Performing key exchange and authentication
    CONNECTED = auto()  # Fully connected and authenticated
    ERROR = auto()  # Error state
    RECONNECTING = auto()  # Attempting reconnection
    CLOSING = auto()  # Gracefully closing connection


class ConnectionEvent(Enum):
    """Events that trigger state transitions."""

    CONNECT_REQUESTED = auto()  # User requested connection
    DISCOVERY_STARTED = auto()  # Started peer discovery
    DISCOVERY_COMPLETE = auto()  # Peer address discovered
    DISCOVERY_FAILED = auto()  # Peer discovery failed
    TCP_CONNECTED = auto()  # TCP connection established
    TCP_FAILED = auto()  # TCP connection failed
    AUTH_STARTED = auto()  # Started authentication
    AUTH_COMPLETE = auto()  # Authentication successful
    AUTH_FAILED = auto()  # Authentication failed
    CONNECTION_LOST = auto()  # Connection dropped
    ERROR_OCCURRED = auto()  # Error detected
    RECONNECT_REQUESTED = auto()  # Reconnection requested
    RECONNECT_TIMEOUT = auto()  # Reconnection timeout expired
    CLOSE_REQUESTED = auto()  # Graceful close requested
    CLOSED = auto()  # Connection closed


@dataclass
class StateTransition:
    """Represents a state transition."""

    from_state: ConnectionState
    event: ConnectionEvent
    to_state: ConnectionState
    timestamp: float = field(default_factory=time.time)


class ConnectionStateMachine:
    """
    Finite state machine for managing P2P connection lifecycle.

    Enforces valid state transitions, tracks state history, and provides
    timeout handling for each state.
    """

    # Define valid state transitions
    TRANSITIONS: Dict[ConnectionState, Dict[ConnectionEvent, ConnectionState]] = {
        ConnectionState.DISCONNECTED: {
            ConnectionEvent.CONNECT_REQUESTED: ConnectionState.DISCOVERING,
        },
        ConnectionState.DISCOVERING: {
            ConnectionEvent.DISCOVERY_COMPLETE: ConnectionState.CONNECTING,
            ConnectionEvent.DISCOVERY_FAILED: ConnectionState.ERROR,
            ConnectionEvent.ERROR_OCCURRED: ConnectionState.ERROR,
        },
        ConnectionState.CONNECTING: {
            ConnectionEvent.TCP_CONNECTED: ConnectionState.AUTHENTICATING,
            ConnectionEvent.TCP_FAILED: ConnectionState.ERROR,
            ConnectionEvent.ERROR_OCCURRED: ConnectionState.ERROR,
        },
        ConnectionState.AUTHENTICATING: {
            ConnectionEvent.AUTH_COMPLETE: ConnectionState.CONNECTED,
            ConnectionEvent.AUTH_FAILED: ConnectionState.ERROR,
            ConnectionEvent.ERROR_OCCURRED: ConnectionState.ERROR,
        },
        ConnectionState.CONNECTED: {
            ConnectionEvent.CONNECTION_LOST: ConnectionState.RECONNECTING,
            ConnectionEvent.ERROR_OCCURRED: ConnectionState.ERROR,
            ConnectionEvent.CLOSE_REQUESTED: ConnectionState.CLOSING,
        },
        ConnectionState.ERROR: {
            ConnectionEvent.RECONNECT_REQUESTED: ConnectionState.RECONNECTING,
            ConnectionEvent.CLOSE_REQUESTED: ConnectionState.CLOSING,
        },
        ConnectionState.RECONNECTING: {
            ConnectionEvent.DISCOVERY_STARTED: ConnectionState.DISCOVERING,
            ConnectionEvent.RECONNECT_TIMEOUT: ConnectionState.ERROR,
            ConnectionEvent.ERROR_OCCURRED: ConnectionState.ERROR,
            ConnectionEvent.CLOSE_REQUESTED: ConnectionState.CLOSING,
        },
        ConnectionState.CLOSING: {
            ConnectionEvent.CLOSED: ConnectionState.DISCONNECTED,
        },
    }

    # State timeouts (seconds)
    STATE_TIMEOUTS: Dict[ConnectionState, Optional[float]] = {
        ConnectionState.DISCONNECTED: None,
        ConnectionState.DISCOVERING: STATE_TRANSITION_TIMEOUT,
        ConnectionState.CONNECTING: STATE_CONNECTING_TIMEOUT,
        ConnectionState.AUTHENTICATING: STATE_AUTHENTICATING_TIMEOUT,
        ConnectionState.CONNECTED: None,
        ConnectionState.ERROR: None,
        ConnectionState.RECONNECTING: STATE_RECONNECTING_DELAY,
        ConnectionState.CLOSING: STATE_TRANSITION_TIMEOUT,
    }

    def __init__(self, initial_state: ConnectionState = ConnectionState.DISCONNECTED):
        """
        Initialize state machine.

        Args:
            initial_state: Initial state (default: DISCONNECTED)
        """
        self.current_state = initial_state
        self.previous_state: Optional[ConnectionState] = None
        self.state_entry_time = time.time()
        self.error_message: Optional[str] = None
        self.transition_history: list[StateTransition] = []
        self.max_history = 100  # Keep last 100 transitions

        # Callbacks
        self.on_state_change: Optional[Callable[[ConnectionState, ConnectionState], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_connected: Optional[Callable[[], None]] = None
        self.on_disconnected: Optional[Callable[[], None]] = None

        logger.debug(f"State machine initialized in state: {self.current_state.name}")

    def transition(self, event: ConnectionEvent, error_msg: Optional[str] = None) -> bool:
        """
        Attempt state transition based on event.

        Args:
            event: Event triggering transition
            error_msg: Error message if event is ERROR_OCCURRED

        Returns:
            True if transition successful, False otherwise
        """
        # Check if transition is valid
        if not self.is_valid_transition(self.current_state, event):
            logger.warning(
                f"Invalid transition: {self.current_state.name} + "
                f"{event.name} (no valid target state)"
            )
            return False

        # Get target state
        new_state = self.TRANSITIONS[self.current_state][event]

        # Store error message if applicable
        if event == ConnectionEvent.ERROR_OCCURRED:
            self.error_message = error_msg or "Unknown error"
        elif new_state == ConnectionState.CONNECTED:
            self.error_message = None  # Clear error on successful connection

        # Perform transition
        old_state = self.current_state
        self.previous_state = old_state
        self.current_state = new_state
        self.state_entry_time = time.time()

        # Record transition
        transition = StateTransition(old_state, event, new_state)
        self.transition_history.append(transition)

        # Trim history if needed
        if len(self.transition_history) > self.max_history:
            self.transition_history = self.transition_history[-self.max_history :]

        logger.info(
            f"State transition: {old_state.name} -> {new_state.name} " f"(event: {event.name})"
        )

        # Call callbacks
        if self.on_state_change:
            try:
                self.on_state_change(old_state, new_state)
            except Exception as e:
                logger.error(f"State change callback error: {e}")

        if new_state == ConnectionState.CONNECTED and self.on_connected:
            try:
                self.on_connected()
            except Exception as e:
                logger.error(f"Connected callback error: {e}")

        if new_state == ConnectionState.DISCONNECTED and self.on_disconnected:
            try:
                self.on_disconnected()
            except Exception as e:
                logger.error(f"Disconnected callback error: {e}")

        if new_state == ConnectionState.ERROR and self.on_error:
            try:
                self.on_error(self.error_message or "Unknown error")
            except Exception as e:
                logger.error(f"Error callback error: {e}")

        return True

    def is_valid_transition(self, from_state: ConnectionState, event: ConnectionEvent) -> bool:
        """
        Check if a transition is valid.

        Args:
            from_state: Source state
            event: Event triggering transition

        Returns:
            True if valid, False otherwise
        """
        return from_state in self.TRANSITIONS and event in self.TRANSITIONS[from_state]

    def get_state(self) -> ConnectionState:
        """Get current state."""
        return self.current_state

    def get_previous_state(self) -> Optional[ConnectionState]:
        """Get previous state."""
        return self.previous_state

    def get_time_in_state(self) -> float:
        """Get time spent in current state (seconds)."""
        return time.time() - self.state_entry_time

    def is_timeout_exceeded(self) -> bool:
        """Check if current state has exceeded its timeout."""
        timeout = self.STATE_TIMEOUTS.get(self.current_state)
        if timeout is None:
            return False
        return self.get_time_in_state() > timeout

    def get_timeout_remaining(self) -> Optional[float]:
        """Get remaining time before timeout (seconds)."""
        timeout = self.STATE_TIMEOUTS.get(self.current_state)
        if timeout is None:
            return None
        remaining = timeout - self.get_time_in_state()
        return max(0, remaining)

    def is_connected(self) -> bool:
        """Check if currently in connected state."""
        return self.current_state == ConnectionState.CONNECTED

    def is_connecting(self) -> bool:
        """Check if currently in a connecting state."""
        return self.current_state in [
            ConnectionState.DISCOVERING,
            ConnectionState.CONNECTING,
            ConnectionState.AUTHENTICATING,
            ConnectionState.RECONNECTING,
        ]

    def is_disconnected(self) -> bool:
        """Check if currently disconnected."""
        return self.current_state == ConnectionState.DISCONNECTED

    def is_error(self) -> bool:
        """Check if currently in error state."""
        return self.current_state == ConnectionState.ERROR

    def get_error_message(self) -> Optional[str]:
        """Get current error message."""
        return self.error_message

    def reset(self, state: ConnectionState = ConnectionState.DISCONNECTED):
        """
        Reset state machine to initial state.

        Args:
            state: State to reset to (default: DISCONNECTED)
        """
        old_state = self.current_state
        self.current_state = state
        self.previous_state = old_state
        self.state_entry_time = time.time()
        self.error_message = None
        logger.info(f"State machine reset: {old_state.name} -> {state.name}")

    def get_history(self, count: int = 10) -> list[StateTransition]:
        """
        Get recent transition history.

        Args:
            count: Number of recent transitions to return

        Returns:
            List of recent transitions
        """
        return self.transition_history[-count:]

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get state machine statistics.

        Returns:
            Dictionary with statistics
        """
        # Count transitions by event type
        event_counts: Dict[str, int] = {}
        for transition in self.transition_history:
            event_name = transition.event.name
            event_counts[event_name] = event_counts.get(event_name, 0) + 1

        # Count time in each state
        state_times: Dict[str, float] = {}
        if len(self.transition_history) >= 2:
            for i in range(len(self.transition_history) - 1):
                state = self.transition_history[i].to_state.name
                duration = (
                    self.transition_history[i + 1].timestamp - self.transition_history[i].timestamp
                )
                state_times[state] = state_times.get(state, 0) + duration

        # Add current state time
        current_state_time = self.get_time_in_state()
        state_times[self.current_state.name] = (
            state_times.get(self.current_state.name, 0) + current_state_time
        )

        return {
            "current_state": self.current_state.name,
            "previous_state": self.previous_state.name if self.previous_state else None,
            "time_in_state": current_state_time,
            "timeout_remaining": self.get_timeout_remaining(),
            "error_message": self.error_message,
            "total_transitions": len(self.transition_history),
            "event_counts": event_counts,
            "state_times": state_times,
            "is_connected": self.is_connected(),
            "is_connecting": self.is_connecting(),
            "is_error": self.is_error(),
        }

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"ConnectionStateMachine(state={self.current_state.name}, "
            f"time_in_state={self.get_time_in_state():.1f}s)"
        )
