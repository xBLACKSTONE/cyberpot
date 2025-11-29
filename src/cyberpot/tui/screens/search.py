"""
Search and filter screen for querying honeypot data.
"""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Input, Button, DataTable

from ...storage.memory_store import MemoryStore


class SearchScreen(Screen):
    """
    Screen for searching and filtering honeypot data.
    """

    BINDINGS = [
        ("ctrl+f", "focus_search", "Search"),
        ("escape", "clear_search", "Clear"),
    ]

    def __init__(
        self,
        memory_store: MemoryStore,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """
        Initialize search screen.

        Args:
            memory_store: Memory store for querying data
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.memory_store = memory_store

    def compose(self) -> ComposeResult:
        """Compose the search layout."""
        yield Header()

        with Container(id="search-container"):
            yield Static("Search & Filter", classes="screen-title")

            # Search input
            with Horizontal(id="search-controls"):
                yield Input(placeholder="Search IP, session, command...", id="search-input")
                yield Button("Search", id="search-button", variant="primary")
                yield Button("Clear", id="clear-button")

            # Results table
            yield Static("Search Results", classes="section-title")
            yield DataTable(id="results-table")

        yield Footer()

    def on_mount(self) -> None:
        """Called when screen is mounted."""
        # Setup results table
        table = self.query_one("#results-table", DataTable)
        table.add_columns("Type", "Timestamp", "Source IP", "Details")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "search-button":
            self._perform_search()
        elif event.button.id == "clear-button":
            self.action_clear_search()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle search input submission."""
        self._perform_search()

    def _perform_search(self) -> None:
        """Perform search based on input."""
        search_input = self.query_one("#search-input", Input)
        query = search_input.value.strip().lower()

        if not query:
            return

        # Search in events
        table = self.query_one("#results-table", DataTable)
        table.clear()

        events = self.memory_store.events.get_all()
        results_count = 0

        for event in events:
            # Simple search: check if query appears in IP, session, or command
            matches = False

            if query in str(event.src_ip).lower():
                matches = True
            elif query in event.session_id.lower():
                matches = True
            elif hasattr(event, 'command') and query in event.command.lower():
                matches = True
            elif hasattr(event, 'username') and query in event.username.lower():
                matches = True

            if matches:
                table.add_row(
                    event.event_type.value,
                    event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    str(event.src_ip),
                    str(event)[:50],
                )
                results_count += 1

                if results_count >= 100:  # Limit results
                    break

    def action_focus_search(self) -> None:
        """Focus search input."""
        self.query_one("#search-input", Input).focus()

    def action_clear_search(self) -> None:
        """Clear search."""
        self.query_one("#search-input", Input).value = ""
        self.query_one("#results-table", DataTable).clear()
