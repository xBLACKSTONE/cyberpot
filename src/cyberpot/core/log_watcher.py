"""
Async log file watcher for tailing Cowrie JSON logs in real-time.

Uses watchfiles for efficient file system monitoring and handles log rotation gracefully.
"""

import asyncio
from pathlib import Path
from typing import AsyncIterator, Optional

import aiofiles
import structlog
from watchfiles import Change, awatch

logger = structlog.get_logger(__name__)


class LogWatcher:
    """
    Watch Cowrie log file and yield new lines in real-time.

    Handles log rotation gracefully by tracking file position and inode.
    """

    def __init__(self, log_path: Path, batch_size: int = 100):
        """
        Initialize log watcher.

        Args:
            log_path: Path to Cowrie JSON log file
            batch_size: Number of lines to batch before yielding
        """
        self.log_path = log_path
        self.batch_size = batch_size
        self.position = 0
        self.inode: Optional[int] = None
        self._running = False

        logger.info("log_watcher_initialized", log_path=str(log_path), batch_size=batch_size)

    async def watch(self) -> AsyncIterator[list[str]]:
        """
        Watch log file and yield batches of new lines.

        Yields:
            Lists of new log lines (batched for efficiency)
        """
        self._running = True

        # Initial read from current end
        if self.log_path.exists():
            await self._initialize_position()
        else:
            logger.warning("log_file_not_found", log_path=str(self.log_path))

        logger.info("log_watcher_started", log_path=str(self.log_path))

        try:
            # Watch for file changes
            async for changes in awatch(self.log_path, stop_event=self._create_stop_event()):
                # Check if file was modified or created
                for change_type, path in changes:
                    if change_type in (Change.added, Change.modified):
                        async for batch in self._read_new_lines():
                            if batch:
                                yield batch
        except asyncio.CancelledError:
            logger.info("log_watcher_cancelled")
            raise
        except Exception as e:
            logger.error("log_watcher_error", error=str(e), exc_info=True)
            raise
        finally:
            self._running = False
            logger.info("log_watcher_stopped")

    async def tail_existing(self, n_lines: int = 100) -> list[str]:
        """
        Read last N lines from log file (initial backfill).

        Args:
            n_lines: Number of lines to read from end

        Returns:
            List of last N log lines
        """
        if not self.log_path.exists():
            return []

        try:
            async with aiofiles.open(self.log_path, "r") as f:
                # Read all lines (for simplicity; could optimize for large files)
                lines = await f.readlines()
                return [line.strip() for line in lines[-n_lines:] if line.strip()]
        except Exception as e:
            logger.error("tail_existing_error", error=str(e), exc_info=True)
            return []

    async def _initialize_position(self) -> None:
        """Initialize file position and inode tracking."""
        try:
            stat = self.log_path.stat()
            self.inode = stat.st_ino

            # Start from end of file
            async with aiofiles.open(self.log_path, "r") as f:
                await f.seek(0, 2)  # Seek to end
                self.position = await f.tell()

            logger.debug("log_position_initialized", position=self.position, inode=self.inode)
        except Exception as e:
            logger.error("initialize_position_error", error=str(e), exc_info=True)
            raise

    async def _read_new_lines(self) -> AsyncIterator[list[str]]:
        """
        Read new lines from current position.

        Handles log rotation by checking inode and resetting position if needed.
        """
        if not self.log_path.exists():
            logger.warning("log_file_disappeared", log_path=str(self.log_path))
            return

        try:
            # Check for log rotation
            current_stat = self.log_path.stat()
            if self.inode and current_stat.st_ino != self.inode:
                logger.info("log_rotation_detected", old_inode=self.inode, new_inode=current_stat.st_ino)
                self.inode = current_stat.st_ino
                self.position = 0  # Reset position

            # Check if file was truncated
            if current_stat.st_size < self.position:
                logger.info("log_file_truncated", old_position=self.position, new_size=current_stat.st_size)
                self.position = 0

            async with aiofiles.open(self.log_path, "r") as f:
                await f.seek(self.position)

                batch = []
                async for line in f:
                    line = line.strip()
                    if line:
                        batch.append(line)

                        if len(batch) >= self.batch_size:
                            yield batch
                            batch = []

                # Yield remaining lines
                if batch:
                    yield batch

                self.position = await f.tell()

        except FileNotFoundError:
            logger.warning("log_file_not_found_during_read", log_path=str(self.log_path))
        except Exception as e:
            logger.error("read_new_lines_error", error=str(e), exc_info=True)
            raise

    def _create_stop_event(self) -> asyncio.Event:
        """Create a stop event for watchfiles (returns None to run indefinitely)."""
        return None  # type: ignore

    def stop(self) -> None:
        """Stop the log watcher."""
        self._running = False
        logger.info("log_watcher_stop_requested")


class LogTailer:
    """
    Higher-level interface for tailing logs with automatic restart on errors.
    """

    def __init__(self, log_path: Path, batch_size: int = 100, backfill_lines: int = 100):
        """
        Initialize log tailer.

        Args:
            log_path: Path to Cowrie JSON log file
            batch_size: Number of lines to batch before yielding
            backfill_lines: Number of historical lines to read on start
        """
        self.log_path = log_path
        self.batch_size = batch_size
        self.backfill_lines = backfill_lines
        self._watcher: Optional[LogWatcher] = None

    async def start(self) -> AsyncIterator[list[str]]:
        """
        Start tailing log file with automatic backfill.

        Yields:
            Batches of log lines (both historical and new)
        """
        self._watcher = LogWatcher(self.log_path, self.batch_size)

        # Yield historical lines first (backfill)
        if self.backfill_lines > 0:
            logger.info("backfilling_logs", n_lines=self.backfill_lines)
            historical_lines = await self._watcher.tail_existing(self.backfill_lines)
            if historical_lines:
                # Batch the historical lines
                for i in range(0, len(historical_lines), self.batch_size):
                    yield historical_lines[i : i + self.batch_size]

        # Start watching for new lines
        async for batch in self._watcher.watch():
            yield batch

    def stop(self) -> None:
        """Stop the log tailer."""
        if self._watcher:
            self._watcher.stop()
