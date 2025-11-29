"""
TTY replay player widget for playing back terminal session recordings.

Parses and plays back Cowrie TTY logs with playback controls.
"""

import asyncio
from pathlib import Path
from typing import List, Tuple

from rich.console import RenderableType
from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static
from textual.containers import Container, Horizontal
from textual.app import ComposeResult

import structlog

logger = structlog.get_logger(__name__)


class TTYPlayer(Container):
    """
    TTY replay player widget with playback controls.

    Plays back terminal session recordings from Cowrie TTY logs.
    """

    is_playing: reactive[bool] = reactive(False)
    playback_speed: reactive[float] = reactive(1.0)
    current_frame: reactive[int] = reactive(0)

    def __init__(
        self,
        tty_log_path: Path | None = None,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ):
        """
        Initialize TTY player.

        Args:
            tty_log_path: Path to Cowrie TTY log file
            name: Widget name
            id: Widget ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        self.tty_log_path = tty_log_path
        self._frames: List[Tuple[float, str]] = []  # (timestamp, content)
        self._playback_task: asyncio.Task | None = None
        self._loaded = False

    def compose(self) -> ComposeResult:
        """Compose the TTY player."""
        # Playback controls
        with Horizontal(id="tty-controls"):
            yield Static("[P]lay/Pause  [R]estart  [1]0.5x  [2]1x  [3]2x  [4]5x", id="tty-help")

        # Display area
        yield Static("", id="tty-display")

        # Status bar
        yield Static("Ready", id="tty-status")

    async def load_tty_log(self, tty_log_path: Path) -> None:
        """
        Load TTY log file.

        Args:
            tty_log_path: Path to Cowrie TTY log file
        """
        self.tty_log_path = tty_log_path

        if not tty_log_path.exists():
            self._show_error(f"TTY log not found: {tty_log_path}")
            return

        try:
            # Parse TTY log
            # Cowrie TTY logs are in "typescript" format with timing information
            # Format: timestamp, data
            self._frames = await self._parse_tty_log(tty_log_path)
            self._loaded = True
            self._update_status(f"Loaded {len(self._frames)} frames")
            logger.info("tty_log_loaded", path=str(tty_log_path), frames=len(self._frames))
        except Exception as e:
            self._show_error(f"Error loading TTY log: {e}")
            logger.error("tty_log_load_error", path=str(tty_log_path), error=str(e))

    async def _parse_tty_log(self, log_path: Path) -> List[Tuple[float, str]]:
        """
        Parse Cowrie TTY log file.

        Args:
            log_path: Path to log file

        Returns:
            List of (timestamp, content) tuples
        """
        frames = []

        # Simple parsing - in reality, Cowrie TTY logs may have more complex format
        # This is a basic implementation
        try:
            with open(log_path, 'rb') as f:
                content = f.read()

            # Split into chunks (simplified)
            # In a real implementation, we'd parse the typescript format properly
            timestamp = 0.0
            for i in range(0, len(content), 1024):
                chunk = content[i:i+1024].decode('utf-8', errors='replace')
                frames.append((timestamp, chunk))
                timestamp += 0.1  # Simulated timing

        except Exception as e:
            logger.error("tty_parse_error", error=str(e))
            # Return empty frames on error
            return []

        return frames

    async def play(self) -> None:
        """Start playback."""
        if not self._loaded:
            self._show_error("No TTY log loaded")
            return

        if self.is_playing:
            return

        self.is_playing = True
        self._playback_task = asyncio.create_task(self._playback_loop())

    async def pause(self) -> None:
        """Pause playback."""
        self.is_playing = False
        if self._playback_task:
            self._playback_task.cancel()
            try:
                await self._playback_task
            except asyncio.CancelledError:
                pass

    async def restart(self) -> None:
        """Restart playback from beginning."""
        await self.pause()
        self.current_frame = 0
        self._clear_display()

    async def _playback_loop(self) -> None:
        """Main playback loop."""
        try:
            display = self.query_one("#tty-display", Static)

            while self.is_playing and self.current_frame < len(self._frames):
                timestamp, content = self._frames[self.current_frame]

                # Update display
                display.update(content)

                # Calculate delay based on playback speed
                if self.current_frame < len(self._frames) - 1:
                    next_timestamp = self._frames[self.current_frame + 1][0]
                    delay = (next_timestamp - timestamp) / self.playback_speed
                    await asyncio.sleep(max(0.01, delay))

                self.current_frame += 1
                self._update_status(
                    f"Frame {self.current_frame}/{len(self._frames)} (Speed: {self.playback_speed}x)"
                )

            # Playback finished
            self.is_playing = False
            if self.current_frame >= len(self._frames):
                self._update_status("Playback complete")

        except asyncio.CancelledError:
            logger.debug("playback_cancelled")
        except Exception as e:
            logger.error("playback_error", error=str(e))
            self._show_error(f"Playback error: {e}")

    def set_speed(self, speed: float) -> None:
        """
        Set playback speed.

        Args:
            speed: Playback speed multiplier (0.5, 1.0, 2.0, 5.0, etc.)
        """
        self.playback_speed = speed
        self._update_status(f"Speed: {speed}x")

    def _clear_display(self) -> None:
        """Clear the display."""
        display = self.query_one("#tty-display", Static)
        display.update("")

    def _show_error(self, message: str) -> None:
        """Show error message."""
        status = self.query_one("#tty-status", Static)
        status.update(f"Error: {message}")

    def _update_status(self, message: str) -> None:
        """Update status message."""
        status = self.query_one("#tty-status", Static)
        status.update(message)

    async def on_key(self, event) -> None:
        """Handle key presses for playback control."""
        key = event.key

        if key == "p":
            if self.is_playing:
                await self.pause()
            else:
                await self.play()
        elif key == "r":
            await self.restart()
        elif key == "1":
            self.set_speed(0.5)
        elif key == "2":
            self.set_speed(1.0)
        elif key == "3":
            self.set_speed(2.0)
        elif key == "4":
            self.set_speed(5.0)
