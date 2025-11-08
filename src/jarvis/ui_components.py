"""
Jarvis - UI Components for Textual Interface

This module provides reusable UI components for the Jarvis TUI,
including file transfer progress, connection quality indicators,
and enhanced dialogs.

Author: orpheus497
Version: 2.0.0
"""

from typing import Callable, Dict, List, Optional, Tuple

from rich.table import Table
from rich.text import Text
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Button, Label, Static


class FileTransferProgress(Widget):
    """Widget displaying file transfer progress.

    Shows filename, progress bar, speed, and status.
    """

    progress = reactive(0.0)
    status = reactive("pending")

    def __init__(
        self,
        transfer_id: str,
        filename: str,
        total_size: int,
        *,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize file transfer progress widget.

        Args:
            transfer_id: Unique transfer identifier
            filename: Name of file being transferred
            total_size: Total file size in bytes
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.transfer_id = transfer_id
        self.filename = filename
        self.total_size = total_size
        self.bytes_transferred = 0
        self.speed_bps = 0.0

    def update_progress(self, bytes_transferred: int, speed_bps: float) -> None:
        """Update transfer progress.

        Args:
            bytes_transferred: Bytes transferred so far
            speed_bps: Transfer speed in bytes per second
        """
        self.bytes_transferred = bytes_transferred
        self.speed_bps = speed_bps

        if self.total_size > 0:
            self.progress = (bytes_transferred / self.total_size) * 100
        else:
            self.progress = 0

    def set_status(self, status: str) -> None:
        """Set transfer status.

        Args:
            status: Status string (pending, in_progress, complete, error)
        """
        self.status = status

    def render(self) -> Text:
        """Render the widget."""

        # Format file size
        def format_size(size: int) -> str:
            for unit in ["B", "KB", "MB", "GB"]:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} TB"

        # Format speed
        speed_str = format_size(self.speed_bps) + "/s" if self.speed_bps > 0 else "---"

        # Status indicator
        status_symbols = {
            "pending": "⏸",
            "in_progress": "▶",
            "complete": "✓",
            "error": "✗",
            "cancelled": "⊗",
        }
        status_symbol = status_symbols.get(self.status, "?")

        # Build display text
        text = Text()
        text.append(f"{status_symbol} ", style="bold")
        text.append(f"{self.filename}\n", style="cyan")
        text.append(f"  Progress: {self.progress:.1f}% | ", style="dim")
        text.append(f"{format_size(self.bytes_transferred)}", style="green")
        text.append(f" / {format_size(self.total_size)} | ", style="dim")
        text.append(f"Speed: {speed_str}", style="yellow")

        return text


class ConnectionQualityIndicator(Static):
    """Widget displaying connection quality.

    Shows quality bars (1-5) and latency information.
    """

    quality = reactive(3)
    latency_ms = reactive(0.0)

    def __init__(
        self,
        contact_name: str,
        *,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize connection quality indicator.

        Args:
            contact_name: Name of the contact
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.contact_name = contact_name

    def update_quality(self, quality: int, latency_ms: float) -> None:
        """Update quality metrics.

        Args:
            quality: Quality rating (1-5)
            latency_ms: Latency in milliseconds
        """
        self.quality = max(1, min(5, quality))
        self.latency_ms = latency_ms
        self.refresh()

    def render(self) -> Text:
        """Render the quality indicator."""
        # Quality bars
        bars = "█" * self.quality + "░" * (5 - self.quality)

        # Color based on quality
        if self.quality >= 4:
            bar_style = "green"
        elif self.quality >= 3:
            bar_style = "yellow"
        else:
            bar_style = "red"

        # Build display
        text = Text()
        text.append(f"{self.contact_name}: ", style="bold")
        text.append(bars, style=bar_style)
        text.append(f" ({self.latency_ms:.0f}ms)", style="dim")

        return text


class ErrorDialog(Container):
    """Error dialog with message and dismiss button."""

    def __init__(
        self,
        title: str,
        message: str,
        on_dismiss: Optional[Callable] = None,
        *,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize error dialog.

        Args:
            title: Dialog title
            message: Error message
            on_dismiss: Callback when dismissed
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message
        self.on_dismiss = on_dismiss

    def compose(self):
        """Compose the dialog."""
        yield Label(f"[bold red]⚠ {self.title_text}[/]")
        yield Static(self.message_text)
        yield Button("Dismiss", variant="error", id="dismiss-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "dismiss-btn":
            if self.on_dismiss:
                self.on_dismiss()
            self.remove()


class ConfirmationDialog(Container):
    """Confirmation dialog with yes/no buttons."""

    def __init__(
        self,
        title: str,
        message: str,
        on_confirm: Optional[Callable] = None,
        on_cancel: Optional[Callable] = None,
        *,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize confirmation dialog.

        Args:
            title: Dialog title
            message: Confirmation message
            on_confirm: Callback when confirmed
            on_cancel: Callback when cancelled
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.title_text = title
        self.message_text = message
        self.on_confirm = on_confirm
        self.on_cancel = on_cancel

    def compose(self):
        """Compose the dialog."""
        yield Label(f"[bold]{self.title_text}[/]")
        yield Static(self.message_text)
        with Horizontal():
            yield Button("Yes", variant="success", id="confirm-btn")
            yield Button("No", variant="default", id="cancel-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "confirm-btn":
            if self.on_confirm:
                self.on_confirm()
            self.remove()
        elif event.button.id == "cancel-btn":
            if self.on_cancel:
                self.on_cancel()
            self.remove()


class SearchResultsList(Static):
    """Widget displaying search results.

    Shows highlighted search results with context.
    """

    def __init__(
        self,
        results: List[dict],
        *,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize search results list.

        Args:
            results: List of search result dictionaries
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.results = results

    def set_results(self, results: List[dict]) -> None:
        """Update search results.

        Args:
            results: New list of search results
        """
        self.results = results
        self.refresh()

    def render(self) -> Table:
        """Render the search results as a table."""
        table = Table(title="Search Results", show_header=True, header_style="bold cyan")
        table.add_column("From", style="yellow", width=20)
        table.add_column("Date", style="dim", width=20)
        table.add_column("Message", style="white")

        if not self.results:
            table.add_row("", "", "[dim]No results found[/]")
            return table

        for result in self.results[:50]:  # Limit to 50 results
            sender = result.get("sender", "Unknown")
            timestamp = result.get("timestamp", 0)

            # Format timestamp
            from datetime import datetime

            try:
                dt = datetime.fromtimestamp(timestamp)
                date_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                date_str = "Unknown"

            # Get snippet or content
            content = result.get("snippet", result.get("content", ""))
            if len(content) > 60:
                content = content[:57] + "..."

            table.add_row(sender, date_str, content)

        return table


class StatisticsChart(Static):
    """Widget displaying connection statistics.

    Shows metrics like latency, throughput, and packet loss.
    """

    def __init__(
        self,
        stats: dict,
        *,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize statistics chart.

        Args:
            stats: Statistics dictionary
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.stats = stats

    def update_stats(self, stats: dict) -> None:
        """Update statistics.

        Args:
            stats: New statistics dictionary
        """
        self.stats = stats
        self.refresh()

    def render(self) -> Table:
        """Render statistics as a table."""
        table = Table(title="Connection Statistics", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="green")

        if not self.stats:
            table.add_row("No data", "[dim]Statistics unavailable[/]")
            return table

        # Latency
        latency = self.stats.get("latency", {})
        avg_latency = latency.get("average_ms")
        if avg_latency:
            table.add_row("Average Latency", f"{avg_latency:.2f} ms")
            table.add_row("Min Latency", f"{latency.get('min_ms', 0):.2f} ms")
            table.add_row("Max Latency", f"{latency.get('max_ms', 0):.2f} ms")

        # Throughput
        throughput = self.stats.get("throughput", {})
        avg_throughput = throughput.get("average_kbps")
        if avg_throughput:
            table.add_row("Average Throughput", f"{avg_throughput:.2f} KB/s")

        # Packets
        packets = self.stats.get("packets", {})
        if packets:
            table.add_row("Packets Sent", str(packets.get("sent", 0)))
            table.add_row("Packets Received", str(packets.get("received", 0)))
            table.add_row("Packet Loss", f"{packets.get('loss_rate_percent', 0):.2f}%")

        # Bytes
        bytes_stats = self.stats.get("bytes", {})
        if bytes_stats:
            total_mb = bytes_stats.get("total", 0) / (1024 * 1024)
            table.add_row("Total Data", f"{total_mb:.2f} MB")

        # Quality
        quality = self.stats.get("quality", {})
        if quality:
            table.add_row("Connection Quality", quality.get("bars", ""))

        # Uptime
        uptime = self.stats.get("uptime_seconds", 0)
        if uptime:
            hours = int(uptime // 3600)
            minutes = int((uptime % 3600) // 60)
            table.add_row("Uptime", f"{hours}h {minutes}m")

        return table


class BarChart(Static):
    """ASCII bar chart visualization for terminal display."""

    def __init__(
        self,
        data: Dict[str, float],
        *,
        max_value: Optional[float] = None,
        bar_width: int = 40,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """
        Initialize bar chart.

        Args:
            data: Dictionary of label to value
            max_value: Maximum value for scaling (auto if None)
            bar_width: Width of bars in characters
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.data = data
        self.max_value = max_value
        self.bar_width = bar_width

    def update_data(self, data: Dict[str, float], max_value: Optional[float] = None) -> None:
        """
        Update chart data.

        Args:
            data: New data dictionary
            max_value: New maximum value
        """
        self.data = data
        if max_value is not None:
            self.max_value = max_value
        self.update(self._render_chart())

    def _render_chart(self) -> str:
        """Render ASCII bar chart."""
        if not self.data:
            return "No data available"

        # Determine max value for scaling
        max_val = self.max_value if self.max_value else max(self.data.values(), default=1)
        if max_val == 0:
            max_val = 1

        lines = []
        for label, value in self.data.items():
            # Calculate bar length
            if max_val > 0:
                bar_len = int((value / max_val) * self.bar_width)
            else:
                bar_len = 0

            # Create bar
            bar = "█" * bar_len

            # Format value
            if value >= 1000000:
                val_str = f"{value/1000000:.1f}M"
            elif value >= 1000:
                val_str = f"{value/1000:.1f}K"
            else:
                val_str = f"{value:.1f}"

            # Combine label, bar, and value
            line = f"{label:20s} {bar:40s} {val_str}"
            lines.append(line)

        return "\n".join(lines)

    def render(self) -> str:
        """Render the chart."""
        return self._render_chart()


class SparklineChart(Static):
    """Sparkline chart for showing trends in terminal."""

    def __init__(
        self,
        values: List[float],
        *,
        label: str = "",
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """
        Initialize sparkline chart.

        Args:
            values: List of values to plot
            label: Chart label
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.values = values
        self.label = label

    def update_values(self, values: List[float], label: Optional[str] = None) -> None:
        """
        Update chart values.

        Args:
            values: New values list
            label: New label (optional)
        """
        self.values = values
        if label is not None:
            self.label = label
        self.update(self._render_sparkline())

    def _render_sparkline(self) -> str:
        """Render sparkline chart."""
        if not self.values:
            return f"{self.label}: No data"

        # Sparkline characters (lowest to highest)
        chars = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]

        min_val = min(self.values)
        max_val = max(self.values)
        value_range = max_val - min_val

        if value_range == 0:
            # All values are the same
            sparkline = chars[len(chars) // 2] * len(self.values)
        else:
            # Map each value to a character
            sparkline = ""
            for value in self.values:
                normalized = (value - min_val) / value_range
                char_index = int(normalized * (len(chars) - 1))
                sparkline += chars[char_index]

        # Format statistics
        avg_val = sum(self.values) / len(self.values)
        stats = f"min={min_val:.1f} avg={avg_val:.1f} max={max_val:.1f}"

        return f"{self.label}\n{sparkline}\n{stats}"

    def render(self) -> str:
        """Render the sparkline."""
        return self._render_sparkline()


class GaugeChart(Static):
    """ASCII gauge chart for visualizing percentage values."""

    def __init__(
        self,
        value: float,
        *,
        label: str = "",
        max_value: float = 100.0,
        width: int = 50,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """
        Initialize gauge chart.

        Args:
            value: Current value
            label: Gauge label
            max_value: Maximum value
            width: Gauge width in characters
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.value = value
        self.label = label
        self.max_value = max_value
        self.width = width

    def update_value(self, value: float) -> None:
        """
        Update gauge value.

        Args:
            value: New value
        """
        self.value = value
        self.update(self._render_gauge())

    def _render_gauge(self) -> str:
        """Render ASCII gauge."""
        # Calculate percentage
        percentage = min(100, max(0, (self.value / self.max_value) * 100))

        # Calculate fill length
        fill_len = int((percentage / 100) * self.width)

        # Choose color character based on percentage
        if percentage >= 75:
            fill_char = "█"  # Full block (good)
        elif percentage >= 50:
            fill_char = "▓"  # Dark shade (moderate)
        elif percentage >= 25:
            fill_char = "▒"  # Medium shade (low)
        else:
            fill_char = "░"  # Light shade (critical)

        # Create gauge
        filled = fill_char * fill_len
        empty = "░" * (self.width - fill_len)
        gauge = f"[{filled}{empty}]"

        # Format
        return f"{self.label}\n{gauge} {percentage:.1f}%"

    def render(self) -> str:
        """Render the gauge."""
        return self._render_gauge()
