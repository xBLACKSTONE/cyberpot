#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BLOCKLIST_DIR="$PROJECT_DIR/data/blocklists"

echo -e "${GREEN}=== Threat Intelligence Blocklist Downloader ===${NC}"
echo ""

# Create directory
mkdir -p "$BLOCKLIST_DIR"

# Function to download and process blocklist
download_blocklist() {
    local name="$1"
    local url="$2"
    local output_file="$BLOCKLIST_DIR/$name.txt"

    echo -e "${YELLOW}Downloading $name...${NC}"

    if curl -f -L "$url" -o "$output_file.tmp"; then
        # Remove comments and empty lines, extract IPs only
        grep -v '^#' "$output_file.tmp" | \
        grep -v '^$' | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
        sort -u > "$output_file"

        rm "$output_file.tmp"

        local count=$(wc -l < "$output_file")
        echo -e "${GREEN}✓ Downloaded $name ($count IPs)${NC}"
    else
        echo -e "${RED}✗ Failed to download $name${NC}"
        rm -f "$output_file.tmp"
        return 1
    fi
}

echo "Downloading blocklists from trusted sources..."
echo ""

# Feodo Tracker - Botnet C2 IPs
download_blocklist "feodo" \
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# EmergingThreats - Compromised IPs
download_blocklist "emerging-threats" \
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# Blocklist.de - SSH Attackers
download_blocklist "blocklist-de-ssh" \
    "https://lists.blocklist.de/lists/ssh.txt"

# Blocklist.de - Bruteforce Attackers
download_blocklist "blocklist-de-bruteforce" \
    "https://lists.blocklist.de/lists/bruteforcelogin.txt"

# CI Army - Known bad IPs
download_blocklist "ci-army" \
    "http://cinsscore.com/list/ci-badguys.txt"

# Talos Intelligence - IP Blacklist
download_blocklist "talos" \
    "https://www.talosintelligence.com/documents/ip-blacklist"

# Spamhaus DROP - Do Not Route Or Peer
echo -e "${YELLOW}Downloading Spamhaus DROP...${NC}"
if curl -f -L "https://www.spamhaus.org/drop/drop.txt" -o "$BLOCKLIST_DIR/spamhaus-drop.txt.tmp"; then
    # Extract IP ranges
    grep -v '^;' "$BLOCKLIST_DIR/spamhaus-drop.txt.tmp" | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | \
    sort -u > "$BLOCKLIST_DIR/spamhaus-drop.txt"

    rm "$BLOCKLIST_DIR/spamhaus-drop.txt.tmp"

    local count=$(wc -l < "$BLOCKLIST_DIR/spamhaus-drop.txt")
    echo -e "${GREEN}✓ Downloaded Spamhaus DROP ($count ranges)${NC}"
else
    echo -e "${RED}✗ Failed to download Spamhaus DROP${NC}"
fi

# Create combined blocklist
echo ""
echo -e "${YELLOW}Creating combined blocklist...${NC}"
cat "$BLOCKLIST_DIR"/*.txt 2>/dev/null | \
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
sort -u > "$BLOCKLIST_DIR/combined.txt"

local total=$(wc -l < "$BLOCKLIST_DIR/combined.txt")
echo -e "${GREEN}✓ Combined blocklist created ($total unique IPs)${NC}"

echo ""
echo -e "${GREEN}=== Download Complete ===${NC}"
echo ""
echo "Blocklists installed to: $BLOCKLIST_DIR"
echo ""
echo "Files:"
ls -lh "$BLOCKLIST_DIR"
echo ""
echo "To update blocklists, run this script again."
echo "Recommended: Set up a cron job to update daily:"
echo "  0 2 * * * $SCRIPT_DIR/download_blocklists.sh"
