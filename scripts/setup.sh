#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
COWRIE_DIR="/opt/cowrie"
CYBERPOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_VERSION="3.11"

echo -e "${GREEN}=== CyberPot Setup Script ===${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install system dependencies
install_system_dependencies() {
    echo -e "${YELLOW}Installing system dependencies...${NC}"

    if command_exists apt-get; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            python3 python3-pip python3-venv \
            git libssl-dev libffi-dev build-essential \
            libpython3-dev python3-minimal authbind \
            virtualenv curl wget
    elif command_exists yum; then
        # RHEL/CentOS
        sudo yum install -y \
            python3 python3-pip python3-devel \
            git openssl-devel libffi-devel gcc \
            make wget curl
    elif command_exists brew; then
        # macOS
        brew install python@${PYTHON_VERSION} git wget curl
    else
        echo -e "${RED}Error: Unsupported package manager${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ System dependencies installed${NC}"
}

# Function to install Cowrie
install_cowrie() {
    echo -e "${YELLOW}Installing Cowrie honeypot...${NC}"

    if [ -d "$COWRIE_DIR" ]; then
        echo -e "${YELLOW}Cowrie directory already exists. Skipping installation.${NC}"
        return
    fi

    # Create cowrie user if it doesn't exist
    if ! id "cowrie" &>/dev/null; then
        echo "Creating cowrie user..."
        sudo adduser --disabled-password --gecos "" cowrie || true
    fi

    # Clone Cowrie
    echo "Cloning Cowrie repository..."
    sudo git clone https://github.com/cowrie/cowrie.git "$COWRIE_DIR"
    sudo chown -R cowrie:cowrie "$COWRIE_DIR"

    # Setup Cowrie virtual environment
    echo "Setting up Cowrie virtual environment..."
    cd "$COWRIE_DIR"
    sudo -u cowrie python3 -m venv cowrie-env
    sudo -u cowrie cowrie-env/bin/pip install --upgrade pip
    sudo -u cowrie cowrie-env/bin/pip install -r requirements.txt

    # Configure Cowrie
    echo "Configuring Cowrie..."
    if [ ! -f "$COWRIE_DIR/etc/cowrie.cfg" ]; then
        sudo -u cowrie cp "$COWRIE_DIR/etc/cowrie.cfg.dist" "$COWRIE_DIR/etc/cowrie.cfg"

        # Enable JSON logging
        sudo -u cowrie sed -i 's/#.*output_jsonlog/output_jsonlog/' "$COWRIE_DIR/etc/cowrie.cfg"
    fi

    # Setup authbind for ports 22 and 23 (optional)
    if command_exists authbind; then
        echo "Setting up authbind for low ports..."
        sudo touch /etc/authbind/byport/22
        sudo touch /etc/authbind/byport/23
        sudo chmod 777 /etc/authbind/byport/22
        sudo chmod 777 /etc/authbind/byport/23
    fi

    echo -e "${GREEN}✓ Cowrie installed to $COWRIE_DIR${NC}"
    echo -e "${YELLOW}Note: Configure $COWRIE_DIR/etc/cowrie.cfg before starting${NC}"
}

# Function to install CyberPot
install_cyberpot() {
    echo -e "${YELLOW}Installing CyberPot...${NC}"

    cd "$CYBERPOT_DIR"

    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        echo "Creating Python virtual environment..."
        python3 -m venv venv
    fi

    # Install CyberPot
    echo "Installing CyberPot and dependencies..."
    source venv/bin/activate
    pip install --upgrade pip
    pip install -e ".[dev]"
    deactivate

    # Create necessary directories
    mkdir -p "$CYBERPOT_DIR/data/geoip"
    mkdir -p "$CYBERPOT_DIR/data/blocklists"
    mkdir -p "$CYBERPOT_DIR/config"
    mkdir -p "$CYBERPOT_DIR/logs"

    echo -e "${GREEN}✓ CyberPot installed${NC}"
}

# Function to download GeoIP database
download_geoip() {
    echo -e "${YELLOW}Downloading GeoIP database...${NC}"

    if [ -f "$CYBERPOT_DIR/data/geoip/GeoLite2-City.mmdb" ]; then
        echo -e "${YELLOW}GeoIP database already exists. Skipping download.${NC}"
        return
    fi

    bash "$CYBERPOT_DIR/scripts/download_geoip.sh"

    echo -e "${GREEN}✓ GeoIP database downloaded${NC}"
}

# Function to download blocklists
download_blocklists() {
    echo -e "${YELLOW}Downloading threat intelligence blocklists...${NC}"

    bash "$CYBERPOT_DIR/scripts/download_blocklists.sh"

    echo -e "${GREEN}✓ Blocklists downloaded${NC}"
}

# Function to create example config
create_config() {
    echo -e "${YELLOW}Creating example configuration...${NC}"

    if [ ! -f "$CYBERPOT_DIR/config/cyberpot.yaml" ]; then
        cp "$CYBERPOT_DIR/config/cyberpot.example.yaml" "$CYBERPOT_DIR/config/cyberpot.yaml"
        echo -e "${GREEN}✓ Configuration created at config/cyberpot.yaml${NC}"
        echo -e "${YELLOW}Note: Edit config/cyberpot.yaml before starting CyberPot${NC}"
    else
        echo -e "${YELLOW}Configuration already exists. Skipping.${NC}"
    fi
}

# Function to create systemd service
create_systemd_service() {
    echo -e "${YELLOW}Creating systemd service...${NC}"

    cat <<EOF | sudo tee /etc/systemd/system/cyberpot.service > /dev/null
[Unit]
Description=CyberPot Honeypot Monitoring System
After=network.target
Requires=cowrie.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$CYBERPOT_DIR
ExecStart=$CYBERPOT_DIR/venv/bin/python -m cyberpot start --config $CYBERPOT_DIR/config/cyberpot.yaml --mode headless
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload

    echo -e "${GREEN}✓ Systemd service created${NC}"
    echo -e "${YELLOW}Enable with: sudo systemctl enable cyberpot${NC}"
    echo -e "${YELLOW}Start with: sudo systemctl start cyberpot${NC}"
}

# Main installation flow
main() {
    echo "This script will install:"
    echo "  - System dependencies"
    echo "  - Cowrie honeypot (to $COWRIE_DIR)"
    echo "  - CyberPot monitoring system"
    echo "  - GeoIP database"
    echo "  - Threat intelligence blocklists"
    echo ""
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi

    # Run installation steps
    install_system_dependencies
    install_cowrie
    install_cyberpot
    download_geoip
    download_blocklists
    create_config

    # Optionally create systemd service
    if command_exists systemctl; then
        read -p "Create systemd service? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            create_systemd_service
        fi
    fi

    echo ""
    echo -e "${GREEN}=== Installation Complete ===${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Configure Cowrie: $COWRIE_DIR/etc/cowrie.cfg"
    echo "  2. Start Cowrie: cd $COWRIE_DIR && bin/cowrie start"
    echo "  3. Configure CyberPot: $CYBERPOT_DIR/config/cyberpot.yaml"
    echo "  4. Start CyberPot: cd $CYBERPOT_DIR && source venv/bin/activate && python -m cyberpot start"
    echo ""
    echo "For TUI mode:"
    echo "  python -m cyberpot start --mode tui"
    echo ""
    echo "For headless mode (with IRC bot only):"
    echo "  python -m cyberpot start --mode headless"
    echo ""
}

# Run main function
main
