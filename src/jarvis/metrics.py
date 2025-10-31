"""
Jarvis - Connection Metrics Tracking

This module tracks and analyzes network connection quality metrics
including latency, throughput, packet loss, and provides quality
indicators for the UI.

Author: orpheus497
Version: 2.0.0
"""

import logging
import time
from collections import deque
from threading import Lock
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class ConnectionMetrics:
    """Tracks connection quality metrics.

    Monitors latency, throughput, packet loss, and other connection
    quality indicators. Provides moving averages and quality ratings.

    Attributes:
        address: Remote address being monitored
        latency_samples: Recent latency measurements
        throughput_samples: Recent throughput measurements
        packets_sent: Total packets sent
        packets_received: Total packets received
        packets_lost: Estimated packets lost
        bytes_sent: Total bytes sent
        bytes_received: Total bytes received
        connection_start: Connection start timestamp
        last_ping: Last ping timestamp
        last_pong: Last pong timestamp
        lock: Thread synchronization lock
    """

    def __init__(self, address: str, max_samples: int = 100):
        """Initialize connection metrics.

        Args:
            address: Remote address to track
            max_samples: Maximum number of samples to keep for averaging
        """
        self.address = address
        self.max_samples = max_samples

        # Latency tracking (milliseconds)
        self.latency_samples: deque = deque(maxlen=max_samples)

        # Throughput tracking (bytes per second)
        self.throughput_samples: deque = deque(maxlen=max_samples)

        # Packet statistics
        self.packets_sent: int = 0
        self.packets_received: int = 0
        self.packets_lost: int = 0

        # Byte statistics
        self.bytes_sent: int = 0
        self.bytes_received: int = 0

        # Timing
        self.connection_start: float = time.time()
        self.last_ping: Optional[float] = None
        self.last_pong: Optional[float] = None

        # Thread safety
        self.lock = Lock()

        logger.debug(f"Initialized metrics for {address}")

    def record_ping(self) -> float:
        """Record a ping timestamp.

        Returns:
            Ping timestamp
        """
        with self.lock:
            self.last_ping = time.time()
            return self.last_ping

    def record_pong(self) -> Optional[float]:
        """Record a pong timestamp and calculate latency.

        Returns:
            Latency in milliseconds, or None if no ping was sent
        """
        with self.lock:
            pong_time = time.time()
            self.last_pong = pong_time

            if self.last_ping is None:
                return None

            # Calculate latency in milliseconds
            latency_ms = (pong_time - self.last_ping) * 1000
            self.latency_samples.append(latency_ms)

            logger.debug(f"Latency to {self.address}: {latency_ms:.2f}ms")

            # Clear ping timestamp
            self.last_ping = None

            return latency_ms

    def measure_latency(self) -> Tuple[float, float]:
        """Initiate a latency measurement.

        Call this when sending a ping, then call record_pong() when
        receiving the pong response.

        Returns:
            Tuple of (ping_timestamp, packet_id)
        """
        return self.record_ping(), self.packets_sent

    def record_packet_sent(self, size: int = 0) -> None:
        """Record a sent packet.

        Args:
            size: Packet size in bytes
        """
        with self.lock:
            self.packets_sent += 1
            self.bytes_sent += size

    def record_packet_received(self, size: int = 0) -> None:
        """Record a received packet.

        Args:
            size: Packet size in bytes
        """
        with self.lock:
            self.packets_received += 1
            self.bytes_received += size

    def record_packet_loss(self, count: int = 1) -> None:
        """Record packet loss.

        Args:
            count: Number of lost packets
        """
        with self.lock:
            self.packets_lost += count
            logger.warning(
                f"Packet loss detected for {self.address}: "
                f"+{count} (total: {self.packets_lost})"
            )

    def calculate_throughput(self, bytes_transferred: int, duration: float) -> float:
        """Calculate and record throughput.

        Args:
            bytes_transferred: Number of bytes transferred
            duration: Time period in seconds

        Returns:
            Throughput in bytes per second
        """
        if duration <= 0:
            return 0.0

        throughput = bytes_transferred / duration

        with self.lock:
            self.throughput_samples.append(throughput)

        return throughput

    def get_average_latency(self) -> Optional[float]:
        """Get average latency.

        Returns:
            Average latency in milliseconds, or None if no samples
        """
        with self.lock:
            if not self.latency_samples:
                return None

            return sum(self.latency_samples) / len(self.latency_samples)

    def get_min_latency(self) -> Optional[float]:
        """Get minimum latency.

        Returns:
            Minimum latency in milliseconds, or None if no samples
        """
        with self.lock:
            if not self.latency_samples:
                return None

            return min(self.latency_samples)

    def get_max_latency(self) -> Optional[float]:
        """Get maximum latency.

        Returns:
            Maximum latency in milliseconds, or None if no samples
        """
        with self.lock:
            if not self.latency_samples:
                return None

            return max(self.latency_samples)

    def get_average_throughput(self) -> Optional[float]:
        """Get average throughput.

        Returns:
            Average throughput in bytes per second, or None if no samples
        """
        with self.lock:
            if not self.throughput_samples:
                return None

            return sum(self.throughput_samples) / len(self.throughput_samples)

    def get_packet_loss_rate(self) -> float:
        """Calculate packet loss rate.

        Returns:
            Packet loss rate as a percentage (0-100)
        """
        with self.lock:
            total_packets = self.packets_sent + self.packets_lost

            if total_packets == 0:
                return 0.0

            return (self.packets_lost / total_packets) * 100

    def get_quality_indicator(self) -> int:
        """Get connection quality indicator (1-5 bars).

        Quality is determined by latency and packet loss:
        - 5 bars: Excellent (< 50ms, < 1% loss)
        - 4 bars: Good (< 100ms, < 3% loss)
        - 3 bars: Fair (< 200ms, < 5% loss)
        - 2 bars: Poor (< 500ms, < 10% loss)
        - 1 bar: Very poor (>= 500ms or >= 10% loss)

        Returns:
            Quality rating from 1 (worst) to 5 (best)
        """
        avg_latency = self.get_average_latency()
        packet_loss = self.get_packet_loss_rate()

        # No data yet
        if avg_latency is None:
            return 3  # Neutral

        # Excellent
        if avg_latency < 50 and packet_loss < 1:
            return 5

        # Good
        if avg_latency < 100 and packet_loss < 3:
            return 4

        # Fair
        if avg_latency < 200 and packet_loss < 5:
            return 3

        # Poor
        if avg_latency < 500 and packet_loss < 10:
            return 2

        # Very poor
        return 1

    def get_quality_description(self) -> str:
        """Get human-readable quality description.

        Returns:
            Quality description string
        """
        quality = self.get_quality_indicator()

        descriptions = {
            5: "Excellent",
            4: "Good",
            3: "Fair",
            2: "Poor",
            1: "Very Poor"
        }

        return descriptions.get(quality, "Unknown")

    def get_statistics(self) -> Dict:
        """Get comprehensive connection statistics.

        Returns:
            Dictionary with all statistics
        """
        with self.lock:
            uptime = time.time() - self.connection_start

            avg_latency = self.get_average_latency()
            min_latency = self.get_min_latency()
            max_latency = self.get_max_latency()
            avg_throughput = self.get_average_throughput()
            packet_loss = self.get_packet_loss_rate()
            quality = self.get_quality_indicator()

            return {
                "address": self.address,
                "uptime_seconds": round(uptime, 2),
                "latency": {
                    "average_ms": round(avg_latency, 2) if avg_latency else None,
                    "min_ms": round(min_latency, 2) if min_latency else None,
                    "max_ms": round(max_latency, 2) if max_latency else None,
                    "samples": len(self.latency_samples),
                },
                "throughput": {
                    "average_bps": round(avg_throughput, 2) if avg_throughput else None,
                    "average_kbps": round(avg_throughput / 1024, 2) if avg_throughput else None,
                    "samples": len(self.throughput_samples),
                },
                "packets": {
                    "sent": self.packets_sent,
                    "received": self.packets_received,
                    "lost": self.packets_lost,
                    "loss_rate_percent": round(packet_loss, 2),
                },
                "bytes": {
                    "sent": self.bytes_sent,
                    "received": self.bytes_received,
                    "total": self.bytes_sent + self.bytes_received,
                },
                "quality": {
                    "indicator": quality,
                    "description": self.get_quality_description(),
                    "bars": "█" * quality + "░" * (5 - quality),
                }
            }

    def reset_metrics(self) -> None:
        """Reset all metrics (keeps connection start time)."""
        with self.lock:
            self.latency_samples.clear()
            self.throughput_samples.clear()
            self.packets_sent = 0
            self.packets_received = 0
            self.packets_lost = 0
            self.bytes_sent = 0
            self.bytes_received = 0
            self.last_ping = None
            self.last_pong = None

        logger.info(f"Reset metrics for {self.address}")

    def __repr__(self) -> str:
        """String representation of metrics."""
        stats = self.get_statistics()
        latency = stats['latency']['average_ms']
        quality = stats['quality']['description']

        return (
            f"ConnectionMetrics({self.address}, "
            f"latency={latency}ms, quality={quality})"
        )
