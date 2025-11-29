# CyberPot Docker Setup

This directory contains Docker Compose configuration for running CyberPot with Cowrie honeypot in containers.

## Quick Start

1. **Download GeoIP database and blocklists:**
   ```bash
   cd ..
   ./scripts/download_geoip.sh
   ./scripts/download_blocklists.sh
   ```

2. **Copy example configuration:**
   ```bash
   cp config/cyberpot.example.yaml config/cyberpot.yaml
   ```

3. **Edit configuration:**
   ```bash
   # Update the Cowrie log path in config/cyberpot.yaml:
   # log_path: "/opt/cowrie/var/log/cowrie/cowrie.json"
   ```

4. **Start containers:**
   ```bash
   docker-compose up -d
   ```

5. **View logs:**
   ```bash
   docker-compose logs -f cyberpot
   ```

## Configuration

### Cowrie Configuration

Place custom Cowrie configuration files in `docker/cowrie/etc/`:

- `cowrie.cfg` - Main Cowrie configuration
- `userdb.txt` - User credentials database
- `fs.pickle` - Filesystem

The Cowrie container will use these configurations if present, otherwise it will use defaults.

### CyberPot Configuration

Edit `config/cyberpot.yaml` to configure:

- Log paths (must point to Docker volume paths)
- IRC settings
- Alert rules
- Storage limits

## Exposed Ports

- **2222/tcp** - Cowrie SSH honeypot
- **2223/tcp** - Cowrie Telnet honeypot

⚠️ **Security Note:** These are honeypot ports. Ensure your firewall is properly configured!

## Volumes

- `cowrie_var` - Cowrie logs and data
- `cowrie_downloads` - Downloaded files from attackers
- `./config` - CyberPot configuration files
- `./data` - GeoIP and blocklist data
- `./logs` - CyberPot application logs

## Running TUI Mode

To run CyberPot in TUI (Terminal UI) mode:

1. Stop the containers:
   ```bash
   docker-compose down
   ```

2. Edit `docker-compose.yml` and uncomment the TUI settings under the `cyberpot` service:
   ```yaml
   stdin_open: true
   tty: true
   command: python -m cyberpot start --mode tui
   ```

3. Start with docker-compose:
   ```bash
   docker-compose up
   ```

4. Attach to the container:
   ```bash
   docker attach cyberpot-monitor
   ```

## Maintenance

### Update Blocklists

```bash
docker-compose exec cyberpot bash -c "cd /app && ./scripts/download_blocklists.sh"
docker-compose restart cyberpot
```

### Update GeoIP Database

```bash
docker-compose exec cyberpot bash -c "cd /app && ./scripts/download_geoip.sh"
docker-compose restart cyberpot
```

### View Cowrie Logs

```bash
docker-compose exec cowrie tail -f /cowrie/cowrie-git/var/log/cowrie/cowrie.json
```

### Access Downloaded Files

Downloaded malware samples are stored in the `cowrie_downloads` volume:

```bash
docker volume inspect cyberpot_cowrie_downloads
```

## Troubleshooting

### Container Won't Start

Check logs:
```bash
docker-compose logs cowrie
docker-compose logs cyberpot
```

### No Events in CyberPot

1. Verify Cowrie is generating logs:
   ```bash
   docker-compose exec cowrie ls -la /cowrie/cowrie-git/var/log/cowrie/
   ```

2. Check log path in `config/cyberpot.yaml`:
   ```yaml
   cowrie:
     log_path: "/opt/cowrie/var/log/cowrie/cowrie.json"
   ```

### Permission Issues

Ensure proper ownership:
```bash
sudo chown -R $USER:$USER config/ data/ logs/
```

## Production Deployment

For production deployment:

1. **Change default ports** to real SSH/Telnet ports (requires privileged mode or port forwarding)
2. **Enable TLS** for IRC connections
3. **Set up log rotation** for application logs
4. **Configure firewall** rules appropriately
5. **Regular updates** of blocklists and GeoIP database
6. **Monitor resources** (CPU, memory, disk)
7. **Backup configurations** regularly

## Security Considerations

- Cowrie is a honeypot and will be attacked
- Isolate honeypot from production networks
- Monitor for container escape attempts
- Regularly update container images
- Review downloaded files in a sandbox environment
- Be aware of legal implications in your jurisdiction
