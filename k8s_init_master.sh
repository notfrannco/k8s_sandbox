#!/bin/bash


############################################## init #########################################################
# Ensure to disable unattended-upgrades  to prevent breaking later                                          #
sudo systemctl mask unattended-upgrades.service                                                             #
sudo systemctl stop unattended-upgrades.service                                                             #
                                                                                                            #
# Ensure process is in fact off:                                                                            #
echo "Ensuring unattended-upgrades are in fact disabled"                                                    #
while systemctl is-active --quiet unattended-upgrades.service; do sleep 1; done                             #
#############################################################################################################


sudo ansible-playbook playbooks/k8s_ha_master.yml --vault-password-file vault_password.txt



############################################## post-run #####################################################
                                                                                                            #
# start the unattended-upgrades again                                                                       #
sudo systemctl unmask unattended-upgrades.service                                                           #
sudo systemctl start unattended-upgrades.service                                                            #
echo "##############################"                                                                       #
echo "running clean up script"                                                                              #
echo "##############################"                                                                       #
#############################################################################################################
