"""
CyberPot - Cowrie Honeypot Monitoring System

Main entry point for the CyberPot application.
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional

import click
import structlog

from cyberpot.analysis.geoip import CombinedGeoIPProvider
from cyberpot.analysis.threat_intel import CombinedThreatIntelProvider
from cyberpot.config import CyberPotConfig
from cyberpot.core.alert_manager import AlertManager
from cyberpot.core.enrichment import EnrichmentEngine
from cyberpot.core.event_processor import EventBus, EventPipeline
from cyberpot.core.log_parser import CowrieLogParser
from cyberpot.core.log_watcher import LogTailer
from cyberpot.irc.bot import CyberPotIRCBot
from cyberpot.storage.memory_store import MemoryStore
from cyberpot.storage.statistics import StatsAggregator
from cyberpot.tui.app import CyberPotApp

logger = structlog.get_logger()


class CyberPot:
    """Main CyberPot application orchestrator."""

    def __init__(self, config: CyberPotConfig):
        """
        Initialize CyberPot.

        Args:
            config: Application configuration
        """
        self.config = config
        self.event_bus = EventBus()
        self.running = False
        self._tasks: list[asyncio.Task] = []

        # Initialize components
        self.store: Optional[MemoryStore] = None
        self.stats: Optional[StatsAggregator] = None
        self.enrichment: Optional[EnrichmentEngine] = None
        self.alert_manager: Optional[AlertManager] = None
        self.pipeline: Optional[EventPipeline] = None
        self.irc_bot: Optional[CyberPotIRCBot] = None
        self.tui_app: Optional[CyberPotApp] = None

    async def initialize(self) -> None:
        """Initialize all components."""
        logger.info("Initializing CyberPot components")

        # Memory store
        self.store = MemoryStore(
            max_events=self.config.storage.max_events,
            max_sessions=self.config.storage.max_sessions,
            max_alerts=self.config.storage.max_alerts,
        )

        # Statistics aggregator
        self.stats = StatsAggregator(
            time_windows=self.config.storage.time_windows,
        )

        # GeoIP provider
        geoip_provider = None
        if self.config.enrichment.geoip.enabled:
            geoip_provider = CombinedGeoIPProvider(
                geoip_db_path=self.config.enrichment.geoip.database_path,
                cache_size=self.config.enrichment.geoip.cache_size,
            )
            logger.info("GeoIP enrichment enabled")

        # Threat intel provider
        threat_intel_provider = None
        if self.config.enrichment.threat_intel.enabled:
            threat_intel_provider = CombinedThreatIntelProvider(
                blocklist_paths=self.config.enrichment.threat_intel.blocklist_paths,
                greynoise_api_key=self.config.enrichment.threat_intel.greynoise_api_key,
                cache_ttl=self.config.enrichment.threat_intel.cache_ttl,
            )
            logger.info("Threat intelligence enrichment enabled")

        # Enrichment engine
        self.enrichment = EnrichmentEngine(
            geoip_provider=geoip_provider,
            threat_intel_provider=threat_intel_provider,
        )

        # Alert manager
        self.alert_manager = AlertManager(
            event_bus=self.event_bus,
            alert_store=self.store.alerts,
            rules_file=self.config.alerts.rules_file,
            dedup_window=self.config.alerts.dedup_window,
        )
        await self.alert_manager.load_rules()
        logger.info(
            "Alert manager initialized",
            rules_count=len(self.alert_manager.rule_evaluator.rules),
        )

        # Event pipeline
        parser = CowrieLogParser()
        self.pipeline = EventPipeline(
            parser=parser,
            enrichment_engine=self.enrichment,
            alert_manager=self.alert_manager,
            event_store=self.store.events,
            event_bus=self.event_bus,
            stats_aggregator=self.stats,
        )

        # Subscribe stats aggregator to events
        self.event_bus.subscribe("*", self.stats.on_event)

        # IRC bot
        if self.config.irc.enabled:
            self.irc_bot = CyberPotIRCBot(self.config.irc)
            # Subscribe to alerts
            self.event_bus.subscribe("alert", self.irc_bot.send_alert)
            logger.info("IRC bot enabled", server=self.config.irc.server)

        logger.info("CyberPot initialization complete")

    async def start_log_watcher(self) -> None:
        """Start watching Cowrie logs."""
        log_path = Path(self.config.cowrie.log_path)

        if not log_path.exists():
            logger.error("Cowrie log file not found", path=str(log_path))
            raise FileNotFoundError(f"Cowrie log file not found: {log_path}")

        tailer = LogTailer(
            log_path=log_path,
            follow=True,
            backfill_lines=self.config.core.backfill_lines,
        )

        logger.info("Starting log watcher", path=str(log_path))

        async for lines in tailer.tail():
            if not self.running:
                break

            for line in lines:
                try:
                    await self.pipeline.process_line(line)
                except Exception as e:
                    logger.error("Error processing log line", error=str(e), line=line)

    async def start_irc_bot(self) -> None:
        """Start IRC bot."""
        if self.irc_bot:
            logger.info("Starting IRC bot")
            await self.irc_bot.connect()

            # Periodically send aggregated alerts
            while self.running:
                await asyncio.sleep(
                    self.config.irc.alerts.rate_limit.aggregation_window
                )
                await self.irc_bot.send_aggregated_alerts()

    async def start_tui(self) -> None:
        """Start TUI application."""
        self.tui_app = CyberPotApp(
            store=self.store,
            stats=self.stats,
            event_bus=self.event_bus,
            config=self.config.tui,
        )

        logger.info("Starting TUI")
        await self.tui_app.run_async()

    async def start(self, mode: str = "tui") -> None:
        """
        Start CyberPot.

        Args:
            mode: Start mode - "tui", "headless", or "both"
        """
        self.running = True
        await self.initialize()

        # Start log watcher
        log_task = asyncio.create_task(self.start_log_watcher())
        self._tasks.append(log_task)

        # Start IRC bot if enabled
        if self.irc_bot:
            irc_task = asyncio.create_task(self.start_irc_bot())
            self._tasks.append(irc_task)

        # Start TUI or run headless
        if mode in ("tui", "both"):
            await self.start_tui()
        else:
            # Headless mode - just wait for shutdown
            logger.info("Running in headless mode")
            while self.running:
                await asyncio.sleep(1)

    async def shutdown(self) -> None:
        """Gracefully shutdown CyberPot."""
        logger.info("Shutting down CyberPot")
        self.running = False

        # Cancel all tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Disconnect IRC bot
        if self.irc_bot:
            await self.irc_bot.disconnect()

        logger.info("CyberPot shutdown complete")


def setup_logging(level: str = "INFO") -> None:
    """
    Configure structured logging.

    Args:
        level: Log level
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(structlog.stdlib, level.upper(), structlog.stdlib.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


@click.group()
@click.version_option(version="1.0.0", prog_name="cyberpot")
def cli():
    """CyberPot - Cowrie Honeypot Monitoring System"""
    pass


@cli.command()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default="config/cyberpot.yaml",
    help="Configuration file path",
)
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["tui", "headless"], case_sensitive=False),
    default="tui",
    help="Start mode (tui or headless)",
)
@click.option(
    "--log-level",
    "-l",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    help="Log level",
)
def start(config: Path, mode: str, log_level: str):
    """Start CyberPot monitoring."""
    setup_logging(log_level)

    logger.info("Starting CyberPot", version="1.0.0", mode=mode)

    # Load configuration
    try:
        app_config = CyberPotConfig.from_yaml(config)
    except Exception as e:
        logger.error("Failed to load configuration", error=str(e), config=str(config))
        sys.exit(1)

    # Create application
    app = CyberPot(app_config)

    # Setup signal handlers
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def signal_handler(sig, frame):
        logger.info("Received shutdown signal", signal=sig)
        loop.create_task(app.shutdown())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run application
    try:
        loop.run_until_complete(app.start(mode=mode))
    except Exception as e:
        logger.error("Application error", error=str(e), exc_info=True)
        sys.exit(1)
    finally:
        loop.run_until_complete(app.shutdown())
        loop.close()


@cli.command()
@click.option(
    "--config",
    "-c",
    type=click.Path(path_type=Path),
    default="config/cyberpot.yaml",
    help="Configuration file to validate",
)
def validate_config(config: Path):
    """Validate configuration file."""
    setup_logging()

    try:
        app_config = CyberPotConfig.from_yaml(config)
        logger.info("Configuration valid", config=str(config))
        click.echo(f"✓ Configuration valid: {config}")
    except Exception as e:
        logger.error("Configuration invalid", error=str(e), config=str(config))
        click.echo(f"✗ Configuration invalid: {e}", err=True)
        sys.exit(1)


@cli.command()
def check_dependencies():
    """Check if all dependencies are available."""
    setup_logging()

    click.echo("Checking dependencies...")

    # Check GeoIP database
    geoip_path = Path("data/geoip/GeoLite2-City.mmdb")
    if geoip_path.exists():
        click.echo(f"✓ GeoIP database found: {geoip_path}")
    else:
        click.echo(f"✗ GeoIP database not found: {geoip_path}", err=True)
        click.echo("  Run: scripts/download_geoip.sh", err=True)

    # Check blocklists
    blocklist_dir = Path("data/blocklists")
    if blocklist_dir.exists() and any(blocklist_dir.iterdir()):
        click.echo(f"✓ Blocklists found: {blocklist_dir}")
    else:
        click.echo(f"✗ Blocklists not found: {blocklist_dir}", err=True)
        click.echo("  Run: scripts/download_blocklists.sh", err=True)

    # Check Cowrie
    cowrie_log = Path("/opt/cowrie/var/log/cowrie/cowrie.json")
    if cowrie_log.exists():
        click.echo(f"✓ Cowrie logs found: {cowrie_log}")
    else:
        click.echo(f"✗ Cowrie logs not found: {cowrie_log}", err=True)
        click.echo("  Ensure Cowrie is installed and running", err=True)


if __name__ == "__main__":
    cli()
