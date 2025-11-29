#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GEOIP_DIR="$PROJECT_DIR/data/geoip"
TEMP_DIR="/tmp/geoip_download"

echo -e "${GREEN}=== GeoIP Database Downloader ===${NC}"
echo ""

# Check if database already exists
if [ -f "$GEOIP_DIR/GeoLite2-City.mmdb" ]; then
    echo -e "${YELLOW}GeoIP database already exists${NC}"
    read -p "Re-download? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping download."
        exit 0
    fi
fi

# Create directories
mkdir -p "$GEOIP_DIR"
mkdir -p "$TEMP_DIR"

# Check for MaxMind license key
if [ -n "$MAXMIND_LICENSE_KEY" ]; then
    echo "Using MaxMind license key from environment"
    LICENSE_KEY="$MAXMIND_LICENSE_KEY"
else
    echo ""
    echo "MaxMind requires a free license key to download GeoLite2 databases."
    echo "Sign up at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    echo ""
    read -p "Enter your MaxMind license key (or press Enter to use alternative source): " LICENSE_KEY
fi

if [ -n "$LICENSE_KEY" ]; then
    # Download from MaxMind with license key
    echo -e "${YELLOW}Downloading GeoLite2-City from MaxMind...${NC}"

    DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${LICENSE_KEY}&suffix=tar.gz"

    curl -L "$DOWNLOAD_URL" -o "$TEMP_DIR/GeoLite2-City.tar.gz"

    # Extract
    echo "Extracting database..."
    cd "$TEMP_DIR"
    tar -xzf GeoLite2-City.tar.gz

    # Find and copy the .mmdb file
    MMDB_FILE=$(find . -name "GeoLite2-City.mmdb" | head -n 1)
    if [ -n "$MMDB_FILE" ]; then
        cp "$MMDB_FILE" "$GEOIP_DIR/GeoLite2-City.mmdb"
        echo -e "${GREEN}✓ GeoLite2-City database downloaded successfully${NC}"
    else
        echo -e "${RED}Error: Could not find GeoLite2-City.mmdb in archive${NC}"
        exit 1
    fi
else
    # Use alternative free source (GitHub mirror or dbip.com)
    echo -e "${YELLOW}Using alternative GeoIP source (DB-IP)...${NC}"
    echo "Note: This is a free alternative but may be less accurate than MaxMind."

    # Download from DB-IP (free alternative)
    DOWNLOAD_URL="https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz"

    echo "Downloading from DB-IP..."
    curl -L "$DOWNLOAD_URL" -o "$TEMP_DIR/dbip-city-lite.mmdb.gz" || {
        echo -e "${RED}Error: Failed to download from DB-IP${NC}"
        echo "You can manually download a GeoIP database and place it at:"
        echo "  $GEOIP_DIR/GeoLite2-City.mmdb"
        exit 1
    }

    # Extract
    echo "Extracting database..."
    gunzip -c "$TEMP_DIR/dbip-city-lite.mmdb.gz" > "$GEOIP_DIR/GeoLite2-City.mmdb"

    echo -e "${GREEN}✓ DB-IP City database downloaded successfully${NC}"
    echo -e "${YELLOW}Note: This is DB-IP data, not MaxMind GeoLite2${NC}"
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo -e "${GREEN}GeoIP database installed to: $GEOIP_DIR/GeoLite2-City.mmdb${NC}"
echo ""
echo "Database info:"
ls -lh "$GEOIP_DIR/GeoLite2-City.mmdb"
echo ""
echo "To update the database, run this script again."
