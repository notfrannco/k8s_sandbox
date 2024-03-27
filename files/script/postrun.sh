#!/bin/bash

# start the unattended-upgrades again
sudo systemctl unmask unattended-upgrades.service
sudo systemctl start unattended-upgrades.service
