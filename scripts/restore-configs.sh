#!/bin/bash

# Lab Router Configuration Restore Script
# WARNING: This will overwrite current configs

BACKUP_DIR="$HOME/config-backups"

echo "Available backups:"
ls -lt "$BACKUP_DIR" | grep "^d" | nl

echo ""
read -p "Enter the number of the backup to restore (or 'q' to quit): " choice

if [ "$choice" = "q" ]; then
    echo "Restore cancelled."
    exit 0
fi

# Get the selected backup directory
RESTORE_PATH=$(ls -t "$BACKUP_DIR" | sed -n "${choice}p")

if [ -z "$RESTORE_PATH" ]; then
    echo "Invalid selection."
    exit 1
fi

FULL_PATH="$BACKUP_DIR/$RESTORE_PATH"

echo ""
echo "You are about to restore configs from:"
echo "$FULL_PATH"
echo ""
cat "$FULL_PATH/MANIFEST.txt"
echo ""
read -p "Are you sure you want to restore? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

echo ""
echo "Starting restore..."

# Restore system configs (require sudo)
echo "Restoring system configs..."
sudo cp "$FULL_PATH/nftables.conf" /etc/nftables.conf
sudo cp "$FULL_PATH/dnsmasq.conf" /etc/dnsmasq.conf
sudo cp "$FULL_PATH"/*.yaml /etc/netplan/

# Restore user configs
echo "Restoring user configs..."
cp -r "$FULL_PATH/prometheus" ~/

echo ""
echo "Restore complete. You may need to:"
echo "1. Reload firewall: sudo nft -f /etc/nftables.conf"
echo "2. Restart dnsmasq: sudo systemctl restart dnsmasq"
echo "3. Apply netplan: sudo netplan apply"
echo "4. Restart Docker containers if needed"
echo ""
read -p "Would you like to reload services now? (yes/no): " reload

if [ "$reload" = "yes" ]; then
    echo "Reloading firewall..."
    sudo nft -f /etc/nftables.conf

    echo "Restarting dnsmasq..."
    sudo systemctl restart dnsmasq

    echo "Applying netplan..."
    sudo netplan apply

    echo ""
    echo "Services reloaded."
fi

echo ""
echo "Restore complete!"