#!/bin/bash

# Requirements
# OS: Ubuntu 22.04 LTS
# run this script with sudo

# VARS
ADMINUSER=ansible
ANSIBLEPASS='$6$8WpkIyj27timdGKk$1BcI.oTWGJggDFoK9F4WTQ9QS3wPrWboi8D55Ee5SCiR2QzbFQrqxMvxAGNrqVitoZkpamxgPcC7xz5LvkJFq.'


echo "#### Installing ansible ######"
sudo apt-get update && sudo apt-get install -y ansible

echo "create and configure ${ADMINUSER} admin user"
sudo useradd -m -s /bin/bash ${ADMINUSER}
sudo usermod -p ${ANSIBLEPASS} ${ADMINUSER}
sudo echo "${ADMINUSER} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${ADMINUSER}
sudo chage -m -1 -M -1 -W -1 -E -1 ${ADMINUSER}
