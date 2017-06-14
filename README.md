# AnsibleCloudCenter

AnsibleCloudCenter is a playbook that automates the HA installation of Cisco CloudCenter

## What works?

This is a very early release of the playbook for know it works:
 - Deploys Cisco CloudCenter CCM on HA on VMWARE
 - Deploys Cisco CloudCenter CCM Database on HA on VMWARE
 - Deploys an HA instance 

### Installation

#### Ansible

```sh
pip install ansible
```
(of from your Linux distribution)

#### Vagrant
If you want to deploy the environment as a lab a Vagrant File is there.
https://www.vagrantup.com/downloads.html
The Vagrant file will deploy 5 machines:
 - CCM1 - Primary CCM
 - CCM2 - Secondary CCM
 - CCMDB1 - Primary (master) DB instance
 - CCMDB2 - Secondary (slave) DB instance
 - CCMLB - HAPROXY to load balance CCM

This VM will have connectivity to your local network so will ask for DHCP from your router/DHCP Server

#### Cisco CloudCenter software

place all the software under software/

### Running the playbook

```sh
vagrant up #optional if you want to deploy your OS locally
bash inventory.sh #if the previous command was runned (this will create a file called "inventory")
vi inventory #change it to your environment
vi ansible.cfg #change it as needed
vi vars.yml #change it as needed
ssh-keygen #Place the keys in the current directory NOT in /home/user/.ssh/
ansible-playbook CloudCenter.yml #see the magic happen
```
