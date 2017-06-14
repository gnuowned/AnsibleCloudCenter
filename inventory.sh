#/bin/bash

INVENTORY_FILE=inventory
ETH=eth1
VM_LIST=$(vagrant status --machine-readable | grep "state,running" | cut -d',' -f 2)

rm $INVENTORY_FILE


for VM in $VM_LIST; do
	IP=$(vagrant ssh $VM -c "ip -f inet addr show $ETH | grep -Po 'inet \K[\d.]+'")
	echo "$VM ansible_ssh_host=$IP" >> $INVENTORY_FILE
done 
