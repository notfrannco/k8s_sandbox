#!/bin/bash
# Ensure to disable unattended-upgrades  to prevent breaking later
sudo systemctl mask unattended-upgrades.service
sudo systemctl stop unattended-upgrades.service

# Ensure process is in fact off:
echo "Ensuring unattended-upgrades are in fact disabled"
while systemctl is-active --quiet unattended-upgrades.service; do sleep 1; done
