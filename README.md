# CyberPot

An integrated honeypot monitoring system that combines Cowrie SSH/Telnet honeypot with real-time TUI monitoring and IRC alerting for security research and threat intelligence.

## Features

- **Real-time TUI Dashboard**: Terminal-based interface with live event feeds, statistics, and interactive session replay
- **IRC Bot Integration**: Intelligent alerting to IRC channels with rate limiting and severity filtering
- **Advanced Analytics**: GeoIP enrichment, threat intelligence integration, and attack pattern detection
- **Interactive TTY Replay**: Play back attacker sessions with full terminal output
- **Comprehensive Alerting**: YAML-based alert rules with severity levels and correlation

## Quick Start

```bash
# Install dependencies
pip install -e .

# Download GeoIP databases
./scripts/download_geoip.sh

# Start with Docker Compose (includes Cowrie)
docker-compose up -d

# Or run directly (requires existing Cowrie installation)
cyberpot --config config/cyberpot.yaml
```

## Architecture

```
Cowrie → Log Watcher → Parser → Event Processor → Enrichment
                                         ↓
                                   Alert Manager
                                   ↓         ↓
                                 TUI      IRC Bot
```

## Requirements

- Python 3.11+
- Cowrie honeypot
- MaxMind GeoIP2 database (free GeoLite2)
- Optional: GreyNoise API key for enhanced threat intelligence

## Configuration

See `config/cyberpot.example.yaml` for full configuration options.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov

# Format code
black src/ tests/

# Type checking
mypy src/
```

## Documentation

- [Architecture](docs/architecture.md)
- [Deployment Guide](docs/deployment.md)
- [Configuration Guide](docs/configuration.md)

## License

MIT License - See LICENSE file for details
