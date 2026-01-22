#!/bin/bash

# Lab Router Configuration Backup Script
# Run this script to backup all critical configs

BACKUP_DIR="$HOME/config-backups"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_PATH="$BACKUP_DIR/$DATE"

echo "Starting backup at $(date)"

# Create backup directory
mkdir -p "$BACKUP_PATH"

# Backup system configs (require sudo)
echo "Backing up system configs..."
sudo cp /etc/nftables.conf "$BACKUP_PATH/nftables.conf"
sudo cp /etc/dnsmasq.conf "$BACKUP_PATH/dnsmasq.conf"
sudo cp /etc/netplan/*.yaml "$BACKUP_PATH/"

# Backup user configs
echo "Backing up user configs..."
cp -r ~/prometheus "$BACKUP_PATH/"

# Save Docker container info
echo "Saving Docker container list..."
docker ps -a --format "{{.Names}}: {{.Image}}" > "$BACKUP_PATH/docker-containers.txt"

# Save running container details
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" > "$BACKUP_PATH/docker-running.txt"

# Create a manifest
echo "Creating backup manifest..."
cat > "$BACKUP_PATH/MANIFEST.txt" << EOF
Lab Router Configuration Backup
Generated: $(date)
Hostname: $(hostname)
IP Address: $(hostname -I)

Files backed up:
- nftables.conf (firewall rules)
- dnsmasq.conf (DHCP/DNS config)
- netplan config (network interfaces)
- prometheus/ (monitoring config)
- docker-containers.txt (container list)
- docker-running.txt (running containers)

To restore:
See restore-configs.sh script or manual restore instructions
EOF

# List what was backed up
echo ""
echo "Backup complete: $BACKUP_PATH"
echo ""
ls -lh "$BACKUP_PATH"

# Keep only last 5 backups
echo ""
echo "Cleaning old backups (keeping last 5)..."
cd "$BACKUP_DIR"
ls -t | tail -n +6 | xargs -r rm -rf

echo ""
echo "Done. Backup saved to: $BACKUP_PATH"