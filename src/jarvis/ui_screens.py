"""
Jarvis - UI Screens for Advanced Features

This module provides specialized screens for Jarvis v2.0 features including
file transfer management, message search, statistics viewing, configuration
editing, and backup management.

Author: orpheus497
Version: 2.3.0
"""

import contextlib
from typing import Callable, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
)

from .ui_components import (
    ConfirmationDialog,
    FileTransferProgress,
    SearchResultsList,
    StatisticsChart,
)


class FileTransferScreen(Screen):
    """Screen for managing file transfers.

    Displays active and completed file transfers with progress indicators,
    allows cancellation, retry, and file browsing.

    Bindings:
        q: Return to main screen
        r: Refresh transfer list
        c: Cancel selected transfer
    """

    BINDINGS = [
        Binding("q", "quit_screen", "Back"),
        Binding("r", "refresh", "Refresh"),
        Binding("c", "cancel_transfer", "Cancel"),
    ]

    def __init__(
        self, name: Optional[str] = None, id: Optional[str] = None, classes: Optional[str] = None
    ):
        """Initialize file transfer screen.

        Args:
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.active_transfers: Dict[str, FileTransferProgress] = {}

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Label("[bold cyan]File Transfer Management[/]", id="screen-title")

        with ScrollableContainer(id="transfers-container"):
            yield Label("Active Transfers:", classes="section-header")
            yield Container(id="active-transfers")

            yield Label("Completed Transfers:", classes="section-header")
            yield Container(id="completed-transfers")

        with Horizontal(id="transfer-actions"):
            yield Button("Browse Files", variant="primary", id="browse-btn")
            yield Button("Clear Completed", variant="default", id="clear-btn")

        yield Footer()

    def add_transfer(self, transfer_id: str, filename: str, total_size: int) -> None:
        """Add a new file transfer to the display.

        Args:
            transfer_id: Unique transfer identifier
            filename: Name of file being transferred
            total_size: Total file size in bytes
        """
        transfer_widget = FileTransferProgress(
            transfer_id=transfer_id, filename=filename, total_size=total_size
        )
        self.active_transfers[transfer_id] = transfer_widget

        container = self.query_one("#active-transfers", Container)
        container.mount(transfer_widget)

    def update_transfer(self, transfer_id: str, bytes_transferred: int, speed_bps: float) -> None:
        """Update transfer progress.

        Args:
            transfer_id: Transfer to update
            bytes_transferred: Bytes transferred so far
            speed_bps: Transfer speed in bytes per second
        """
        if transfer_id in self.active_transfers:
            self.active_transfers[transfer_id].update_progress(bytes_transferred, speed_bps)

    def complete_transfer(self, transfer_id: str) -> None:
        """Mark transfer as completed and move to completed section.

        Args:
            transfer_id: Transfer to complete
        """
        if transfer_id in self.active_transfers:
            widget = self.active_transfers[transfer_id]
            widget.set_status("complete")

            # Move to completed section
            self.query_one("#active-transfers", Container)
            completed_container = self.query_one("#completed-transfers", Container)

            widget.remove()
            completed_container.mount(widget)
            del self.active_transfers[transfer_id]

    def action_quit_screen(self) -> None:
        """Return to main screen."""
        self.app.pop_screen()

    def action_refresh(self) -> None:
        """Refresh transfer list."""
        self.refresh()

    def action_cancel_transfer(self) -> None:
        """Cancel the currently selected transfer."""
        # Implementation depends on selection mechanism
        pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "browse-btn":
            # Open file browser (implementation depends on file dialog)
            pass
        elif event.button.id == "clear-btn":
            # Clear completed transfers
            completed_container = self.query_one("#completed-transfers", Container)
            completed_container.remove_children()


class SearchScreen(Screen):
    """Screen for searching message history.

    Provides full-text search with filters for contacts, groups, and date ranges.
    Displays results with context and allows navigation to original messages.

    Bindings:
        q: Return to main screen
        ctrl+f: Focus search input
        enter: Execute search
    """

    BINDINGS = [
        Binding("q", "quit_screen", "Back"),
        Binding("ctrl+f", "focus_search", "Focus Search"),
        Binding("enter", "execute_search", "Search"),
    ]

    def __init__(
        self,
        search_callback: Optional[Callable] = None,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize search screen.

        Args:
            search_callback: Function to call when executing search
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.search_callback = search_callback
        self.current_results: List[Dict] = []

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Label("[bold cyan]Message Search[/]", id="screen-title")

        with Container(id="search-controls"):
            yield Label("Search Query:")
            yield Input(placeholder="Enter search terms...", id="search-input")

            with Horizontal():
                yield Label("Filter by Contact:")
                yield Input(placeholder="Contact UID (optional)", id="contact-filter")

                yield Label("Filter by Group:")
                yield Input(placeholder="Group ID (optional)", id="group-filter")

            with Horizontal(id="search-actions"):
                yield Button("Search", variant="primary", id="search-btn")
                yield Button("Clear", variant="default", id="clear-btn")

        with ScrollableContainer(id="results-container"):
            yield SearchResultsList(results=[], id="search-results")

        yield Label("", id="result-count")
        yield Footer()

    def execute_search(self, query: str, contact_filter: str = "", group_filter: str = "") -> None:
        """Execute a search query.

        Args:
            query: Search query string
            contact_filter: Optional contact UID filter
            group_filter: Optional group ID filter
        """
        if self.search_callback:
            results = self.search_callback(
                query=query, contact_uid=contact_filter or None, group_id=group_filter or None
            )
            self.current_results = results

            # Update results display
            results_widget = self.query_one("#search-results", SearchResultsList)
            results_widget.set_results(results)

            # Update count
            count_label = self.query_one("#result-count", Label)
            count_label.update(f"Found {len(results)} results")

    def action_quit_screen(self) -> None:
        """Return to main screen."""
        self.app.pop_screen()

    def action_focus_search(self) -> None:
        """Focus the search input."""
        search_input = self.query_one("#search-input", Input)
        search_input.focus()

    def action_execute_search(self) -> None:
        """Execute search with current input values."""
        search_input = self.query_one("#search-input", Input)
        contact_input = self.query_one("#contact-filter", Input)
        group_input = self.query_one("#group-filter", Input)

        self.execute_search(
            query=search_input.value,
            contact_filter=contact_input.value,
            group_filter=group_input.value,
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "search-btn":
            self.action_execute_search()
        elif event.button.id == "clear-btn":
            # Clear all inputs
            self.query_one("#search-input", Input).value = ""
            self.query_one("#contact-filter", Input).value = ""
            self.query_one("#group-filter", Input).value = ""
            self.query_one("#search-results", SearchResultsList).set_results([])
            self.query_one("#result-count", Label).update("")


class StatisticsScreen(Screen):
    """Screen for viewing connection statistics.

    Displays detailed metrics about connections including latency, throughput,
    packet loss, and quality indicators for all active contacts.

    Bindings:
        q: Return to main screen
        r: Refresh statistics
    """

    BINDINGS = [
        Binding("q", "quit_screen", "Back"),
        Binding("r", "refresh", "Refresh"),
    ]

    def __init__(
        self,
        stats_callback: Optional[Callable] = None,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize statistics screen.

        Args:
            stats_callback: Function to get current statistics
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.stats_callback = stats_callback
        self.contact_stats: Dict[str, Dict] = {}

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Label("[bold cyan]Connection Statistics[/]", id="screen-title")

        with ScrollableContainer(id="stats-container"):
            yield Label("Overall Statistics:", classes="section-header")
            yield StatisticsChart(stats={}, id="overall-stats")

            yield Label("Per-Contact Statistics:", classes="section-header")
            yield Container(id="contact-stats")

        yield Footer()

    def update_statistics(self, overall_stats: Dict, contact_stats: Dict[str, Dict]) -> None:
        """Update displayed statistics.

        Args:
            overall_stats: Overall connection statistics
            contact_stats: Per-contact statistics dictionary
        """
        # Update overall stats
        overall_chart = self.query_one("#overall-stats", StatisticsChart)
        overall_chart.update_stats(overall_stats)

        # Update per-contact stats
        self.contact_stats = contact_stats
        contact_container = self.query_one("#contact-stats", Container)
        contact_container.remove_children()

        for _contact_uid, stats in contact_stats.items():
            chart = StatisticsChart(stats=stats)
            contact_container.mount(chart)

    def action_quit_screen(self) -> None:
        """Return to main screen."""
        self.app.pop_screen()

    def action_refresh(self) -> None:
        """Refresh statistics from callback."""
        if self.stats_callback:
            overall, contacts = self.stats_callback()
            self.update_statistics(overall, contacts)


class ConfigurationScreen(Screen):
    """Screen for editing Jarvis configuration.

    Provides a form-based interface for modifying configuration settings
    with validation and save/cancel options.

    Bindings:
        q: Cancel and return
        ctrl+s: Save configuration
    """

    BINDINGS = [
        Binding("q", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
    ]

    def __init__(
        self,
        config: Optional[Dict] = None,
        save_callback: Optional[Callable] = None,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize configuration screen.

        Args:
            config: Current configuration dictionary
            save_callback: Function to call when saving configuration
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.config = config or {}
        self.save_callback = save_callback

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Label("[bold cyan]Configuration Editor[/]", id="screen-title")

        with ScrollableContainer(id="config-container"):
            # Network settings
            yield Label("[bold]Network Settings[/]", classes="section-header")
            with Horizontal():
                yield Label("Server Host:", classes="config-label")
                yield Input(
                    value=self.config.get("network", {}).get("host", "0.0.0.0"), id="network-host"
                )
            with Horizontal():
                yield Label("Server Port:", classes="config-label")
                yield Input(
                    value=str(self.config.get("network", {}).get("port", 5000)), id="network-port"
                )

            # Security settings
            yield Label("[bold]Security Settings[/]", classes="section-header")
            with Horizontal():
                yield Label("Use Double Ratchet:", classes="config-label")
                yield Input(
                    value=str(self.config.get("security", {}).get("use_ratchet", True)),
                    id="security-ratchet",
                )
            with Horizontal():
                yield Label("Message Encryption:", classes="config-label")
                yield Input(
                    value=str(self.config.get("security", {}).get("encryption_enabled", True)),
                    id="security-encryption",
                )

            # Rate limiting
            yield Label("[bold]Rate Limiting[/]", classes="section-header")
            with Horizontal():
                yield Label("Messages per Minute:", classes="config-label")
                yield Input(
                    value=str(self.config.get("rate_limit", {}).get("messages_per_minute", 60)),
                    id="rate-limit-messages",
                )

            # File transfers
            yield Label("[bold]File Transfers[/]", classes="section-header")
            with Horizontal():
                yield Label("Chunk Size (KB):", classes="config-label")
                yield Input(
                    value=str(self.config.get("file_transfer", {}).get("chunk_size", 1024)),
                    id="file-chunk-size",
                )

        with Horizontal(id="config-actions"):
            yield Button("Save", variant="success", id="save-btn")
            yield Button("Cancel", variant="default", id="cancel-btn")

        yield Footer()

    def action_save(self) -> None:
        """Save configuration changes."""
        # Gather all input values
        updated_config = {
            "network": {
                "host": self.query_one("#network-host", Input).value,
                "port": int(self.query_one("#network-port", Input).value),
            },
            "security": {
                "use_ratchet": self.query_one("#security-ratchet", Input).value.lower() == "true",
                "encryption_enabled": self.query_one("#security-encryption", Input).value.lower()
                == "true",
            },
            "rate_limit": {
                "messages_per_minute": int(self.query_one("#rate-limit-messages", Input).value),
            },
            "file_transfer": {
                "chunk_size": int(self.query_one("#file-chunk-size", Input).value),
            },
        }

        if self.save_callback:
            self.save_callback(updated_config)

        self.app.pop_screen()

    def action_cancel(self) -> None:
        """Cancel configuration changes."""
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "save-btn":
            self.action_save()
        elif event.button.id == "cancel-btn":
            self.action_cancel()


class BackupManagementScreen(Screen):
    """Screen for managing backups.

    Allows creating new backups, restoring from backups, scheduling automatic
    backups, and viewing backup history.

    Bindings:
        q: Return to main screen
        c: Create new backup
        r: Restore from backup
    """

    BINDINGS = [
        Binding("q", "quit_screen", "Back"),
        Binding("c", "create_backup", "Create Backup"),
        Binding("r", "restore_backup", "Restore"),
    ]

    def __init__(
        self,
        backup_callback: Optional[Callable] = None,
        restore_callback: Optional[Callable] = None,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        """Initialize backup management screen.

        Args:
            backup_callback: Function to call when creating backup
            restore_callback: Function to call when restoring backup
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.backup_callback = backup_callback
        self.restore_callback = restore_callback
        self.backup_list: List[Dict] = []

    def compose(self) -> ComposeResult:
        """Compose the screen layout."""
        yield Header()
        yield Label("[bold cyan]Backup Management[/]", id="screen-title")

        with Container(id="backup-controls"):
            yield Label("Create New Backup:", classes="section-header")
            with Horizontal():
                yield Label("Encryption Password (optional):")
                yield Input(
                    placeholder="Leave empty for no encryption", password=True, id="backup-password"
                )

            with Horizontal(id="backup-actions"):
                yield Button("Create Backup", variant="primary", id="create-btn")
                yield Button("Restore from Backup", variant="default", id="restore-btn")

        with ScrollableContainer(id="backup-list-container"):
            yield Label("Available Backups:", classes="section-header")
            yield DataTable(id="backup-table")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize table when screen is mounted."""
        table = self.query_one("#backup-table", DataTable)
        table.add_columns("Date", "Size", "Encrypted", "Path")

    def update_backup_list(self, backups: List[Dict]) -> None:
        """Update the list of available backups.

        Args:
            backups: List of backup information dictionaries
        """
        self.backup_list = backups

        table = self.query_one("#backup-table", DataTable)
        table.clear()

        for backup in backups:
            table.add_row(
                backup.get("date", "Unknown"),
                backup.get("size", "Unknown"),
                "Yes" if backup.get("encrypted", False) else "No",
                backup.get("path", "Unknown"),
            )

    def action_quit_screen(self) -> None:
        """Return to main screen."""
        self.app.pop_screen()

    def action_create_backup(self) -> None:
        """Create a new backup."""
        password_input = self.query_one("#backup-password", Input)
        password = password_input.value if password_input.value else None

        if self.backup_callback:
            try:
                self.backup_callback(password=password)
                # Show success dialog
                password_input.value = ""
            except Exception:
                # Show error dialog
                pass

    def action_restore_backup(self) -> None:
        """Restore from selected backup."""
        table = self.query_one("#backup-table", DataTable)
        if table.cursor_row >= 0 and self.restore_callback:
            backup = self.backup_list[table.cursor_row]

            # Show confirmation dialog
            def on_confirm():
                with contextlib.suppress(Exception):
                    self.restore_callback(backup_path=backup["path"])

            dialog = ConfirmationDialog(
                title="Restore Backup",
                message=f"Restore from backup: {backup['date']}?\nThis will replace current data.",
                on_confirm=on_confirm,
            )
            self.mount(dialog)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "create-btn":
            self.action_create_backup()
        elif event.button.id == "restore-btn":
            self.action_restore_backup()
