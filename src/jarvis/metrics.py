"""
Jarvis - Comprehensive Metrics and Monitoring System

This module provides multi-level metrics tracking:
1. Connection-level metrics (latency, throughput, packet loss)
2. Application-level metrics (messages, files, errors)
3. System health monitoring
4. Resource usage tracking

Features:
- Per-connection quality metrics
- Application-wide performance monitoring
- Health check indicators
- Historical data retention
- Thread-safe metric collection

Author: orpheus497
Version: 2.4.0
"""

import logging
import time
from collections import deque
from threading import Lock
from typing import Dict, List, Optional, Tuple

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

        descriptions = {5: "Excellent", 4: "Good", 3: "Fair", 2: "Poor", 1: "Very Poor"}

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
                },
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
        latency = stats["latency"]["average_ms"]
        quality = stats["quality"]["description"]

        return f"ConnectionMetrics({self.address}, " f"latency={latency}ms, quality={quality})"


# Application-wide metrics and monitoring


class ApplicationMetrics:
    """Application-wide metrics collector.

    Provides centralized collection of application-level metrics across
    all subsystems. Thread-safe and supports historical data retention.

    Attributes:
        start_time: Application start timestamp
        counters: Dictionary of counter metrics
        gauges: Dictionary of gauge metrics
        histograms: Dictionary of histogram metrics (sample collections)
        health_checks: Dictionary of component health statuses
    """

    def __init__(self):
        """Initialize application metrics collector."""
        self.start_time = time.time()
        self.lock = Lock()

        # Metric storage
        self.counters: Dict[str, int] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, deque] = {}

        # Health tracking
        self.health_checks: Dict[str, Tuple[bool, Optional[str]]] = {}
        self.last_health_check = time.time()

        # Historical snapshots (last hour, 1-minute intervals)
        self._snapshots: deque = deque(maxlen=60)
        self._last_snapshot = time.time()

        # Initialize core metrics
        self._init_core_metrics()

        logger.info("Application metrics initialized")

    def _init_core_metrics(self) -> None:
        """Initialize core application metrics."""
        # Message metrics
        self.register_counter("messages.sent", 0)
        self.register_counter("messages.received", 0)
        self.register_counter("messages.failed", 0)
        self.register_counter("messages.queued", 0)
        self.register_counter("messages.delivered", 0)

        # Connection metrics
        self.register_gauge("connections.active", 0.0)
        self.register_counter("connections.total", 0)
        self.register_counter("connections.failed", 0)

        # File transfer metrics
        self.register_counter("files.sent", 0)
        self.register_counter("files.received", 0)
        self.register_counter("files.failed", 0)
        self.register_histogram("files.size_bytes")
        self.register_histogram("files.duration_seconds")

        # Error metrics
        self.register_counter("errors.total", 0)
        self.register_counter("errors.crypto", 0)
        self.register_counter("errors.network", 0)
        self.register_counter("errors.protocol", 0)

        # Performance metrics (milliseconds)
        self.register_histogram("latency.message_ms")
        self.register_histogram("latency.encryption_ms")
        self.register_histogram("latency.ratchet_ms")

    def register_counter(self, name: str, initial_value: int = 0) -> None:
        """Register a counter metric.

        Args:
            name: Metric name (use dots for hierarchy)
            initial_value: Initial counter value
        """
        with self.lock:
            if name not in self.counters:
                self.counters[name] = initial_value

    def register_gauge(self, name: str, initial_value: float = 0.0) -> None:
        """Register a gauge metric.

        Args:
            name: Metric name
            initial_value: Initial gauge value
        """
        with self.lock:
            if name not in self.gauges:
                self.gauges[name] = initial_value

    def register_histogram(self, name: str, max_samples: int = 1000) -> None:
        """Register a histogram metric.

        Args:
            name: Metric name
            max_samples: Maximum samples to retain
        """
        with self.lock:
            if name not in self.histograms:
                self.histograms[name] = deque(maxlen=max_samples)

    def increment_counter(self, name: str, delta: int = 1) -> None:
        """Increment a counter.

        Args:
            name: Counter name
            delta: Amount to increment
        """
        with self.lock:
            if name not in self.counters:
                self.register_counter(name)
            self.counters[name] += delta

    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge value.

        Args:
            name: Gauge name
            value: New value
        """
        with self.lock:
            if name not in self.gauges:
                self.register_gauge(name)
            self.gauges[name] = value

    def record_histogram_value(self, name: str, value: float) -> None:
        """Record a value in a histogram.

        Args:
            name: Histogram name
            value: Value to record
        """
        with self.lock:
            if name not in self.histograms:
                self.register_histogram(name)
            self.histograms[name].append((time.time(), value))

    def get_histogram_stats(self, name: str) -> Optional[Dict]:
        """Get histogram statistics.

        Args:
            name: Histogram name

        Returns:
            Dictionary with min, max, mean, p50, p95, p99, or None if no data
        """
        with self.lock:
            if name not in self.histograms or not self.histograms[name]:
                return None

            values = [v for _, v in self.histograms[name]]
            sorted_values = sorted(values)
            count = len(sorted_values)

            stats = {
                "count": count,
                "min": sorted_values[0],
                "max": sorted_values[-1],
                "mean": sum(sorted_values) / count,
                "p50": sorted_values[int(count * 0.5)],
            }

            if count > 20:
                stats["p95"] = sorted_values[int(count * 0.95)]
            if count > 100:
                stats["p99"] = sorted_values[int(count * 0.99)]

            return stats

    def update_health(self, component: str, healthy: bool, error: Optional[str] = None) -> None:
        """Update health status for a component.

        Args:
            component: Component name (e.g., "database", "network")
            healthy: Whether component is healthy
            error: Optional error message
        """
        with self.lock:
            self.health_checks[component] = (healthy, error)
            self.last_health_check = time.time()

    def get_health_status(self) -> Dict:
        """Get overall health status.

        Returns:
            Dictionary with health information
        """
        with self.lock:
            all_checks = list(self.health_checks.values())

            if not all_checks:
                status = "unknown"
                healthy = None
            elif all(check[0] for check in all_checks):
                status = "healthy"
                healthy = True
            elif any(check[0] for check in all_checks):
                status = "degraded"
                healthy = False
            else:
                status = "unhealthy"
                healthy = False

            failed_components = {
                name: error for name, (ok, error) in self.health_checks.items() if not ok
            }

            return {
                "status": status,
                "healthy": healthy,
                "checks": len(self.health_checks),
                "passed": sum(1 for ok, _ in all_checks if ok),
                "failed": sum(1 for ok, _ in all_checks if not ok),
                "components": dict(self.health_checks),
                "failed_components": failed_components,
                "last_check": self.last_health_check,
            }

    def get_summary(self) -> Dict:
        """Get high-level metrics summary.

        Returns:
            Summary of key metrics
        """
        with self.lock:
            uptime = time.time() - self.start_time

            # Calculate rates
            message_rate = self.counters.get("messages.sent", 0) / uptime if uptime > 0 else 0
            error_rate = self.counters.get("errors.total", 0) / uptime if uptime > 0 else 0

            return {
                "uptime_seconds": round(uptime, 2),
                "uptime_formatted": self._format_duration(uptime),
                "messages": {
                    "sent": self.counters.get("messages.sent", 0),
                    "received": self.counters.get("messages.received", 0),
                    "failed": self.counters.get("messages.failed", 0),
                    "queued": self.counters.get("messages.queued", 0),
                    "rate_per_second": round(message_rate, 2),
                },
                "connections": {
                    "active": int(self.gauges.get("connections.active", 0)),
                    "total": self.counters.get("connections.total", 0),
                    "failed": self.counters.get("connections.failed", 0),
                },
                "files": {
                    "sent": self.counters.get("files.sent", 0),
                    "received": self.counters.get("files.received", 0),
                    "failed": self.counters.get("files.failed", 0),
                },
                "errors": {
                    "total": self.counters.get("errors.total", 0),
                    "rate_per_second": round(error_rate, 2),
                },
                "health": self.get_health_status(),
            }

    def get_all_metrics(self) -> Dict:
        """Get all metrics.

        Returns:
            Complete metrics dictionary
        """
        with self.lock:
            histograms = {}
            for name in self.histograms:
                stats = self.get_histogram_stats(name)
                if stats:
                    histograms[name] = stats

            return {
                "timestamp": time.time(),
                "uptime_seconds": time.time() - self.start_time,
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "histograms": histograms,
                "health": self.get_health_status(),
            }

    def record_snapshot(self) -> None:
        """Record periodic metrics snapshot for historical tracking."""
        now = time.time()

        # Snapshot every minute
        if now - self._last_snapshot < 60:
            return

        snapshot = {
            "timestamp": now,
            "metrics": self.get_summary(),
        }

        with self.lock:
            self._snapshots.append(snapshot)
            self._last_snapshot = now

        logger.debug(f"Recorded metrics snapshot ({len(self._snapshots)} total)")

    def get_history(self, duration_minutes: int = 60) -> List[Dict]:
        """Get historical metrics snapshots.

        Args:
            duration_minutes: How many minutes of history to return

        Returns:
            List of metric snapshots
        """
        cutoff = time.time() - (duration_minutes * 60)

        with self.lock:
            return [s for s in self._snapshots if s["timestamp"] >= cutoff]

    def reset_metrics(self) -> None:
        """Reset all metrics (keeps start time)."""
        with self.lock:
            for counter in self.counters:
                self.counters[counter] = 0
            for gauge in self.gauges:
                self.gauges[gauge] = 0.0
            for histogram in self.histograms:
                self.histograms[histogram].clear()

            self._snapshots.clear()

        logger.info("All application metrics reset")

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable form.

        Args:
            seconds: Duration in seconds

        Returns:
            Formatted string (e.g., "2d 5h 30m")
        """
        if seconds < 60:
            return f"{int(seconds)}s"

        parts = []
        days, seconds = divmod(int(seconds), 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)

        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 and not days:
            parts.append(f"{seconds}s")

        return " ".join(parts) if parts else "0s"


# Global application metrics instance
_app_metrics: Optional[ApplicationMetrics] = None
_metrics_lock = Lock()


def get_app_metrics() -> ApplicationMetrics:
    """Get or create the global application metrics instance.

    Returns:
        ApplicationMetrics singleton instance
    """
    global _app_metrics

    if _app_metrics is None:
        with _metrics_lock:
            if _app_metrics is None:
                _app_metrics = ApplicationMetrics()

    return _app_metrics
