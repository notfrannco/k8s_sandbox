#!/bin/bash

# Requirements
# OS: Ubuntu 22.04 LTS
# run this script with sudo

# VARS
ADMINUSER=ansible
ANSIBLEPASS='$6$8WpkIyj27timdGKk$1BcI.oTWGJggDFoK9F4WTQ9QS3wPrWboi8D55Ee5SCiR2QzbFQrqxMvxAGNrqVitoZkpamxgPcC7xz5LvkJFq.'

############################################## init #########################################################
# Ensure to disable unattended-upgrades  to prevent breaking later                                          #
sudo systemctl mask unattended-upgrades.service                                                             #
sudo systemctl stop unattended-upgrades.service                                                             #
                                                                                                            #
# Ensure process is in fact off:                                                                            #
echo "Ensuring unattended-upgrades are in fact disabled"                                                    #
while systemctl is-active --quiet unattended-upgrades.service; do sleep 1; done                             #
#############################################################################################################



echo "#### Installing ansible ######"
sudo apt-get update && sudo apt-get install -y ansible sshpass

echo "create and configure ${ADMINUSER} admin user"
sudo useradd -m -s /bin/bash ${ADMINUSER}
sudo usermod -p ${ANSIBLEPASS} ${ADMINUSER}
sudo echo "${ADMINUSER} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${ADMINUSER}
sudo chage -m -1 -M -1 -W -1 -E -1 ${ADMINUSER}



############################################## post-run #####################################################
                                                                                                            #
# start the unattended-upgrades again                                                                       #
sudo systemctl unmask unattended-upgrades.service                                                           #
sudo systemctl start unattended-upgrades.service                                                            #
echo "##############################"                                                                       #
echo "running clean up script"                                                                              #
echo "##############################"                                                                       #
#############################################################################################################
