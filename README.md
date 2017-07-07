# deploy-and-configure

Designed to automate setting up a VM

This repository builds a docker container that knows how to:
* Clone a vSphere template into 1 or more Virtual Machines
* Configure the networking (static only) for these VMs

## Command Line Options

Running the container without any options will show the usage information (optional arguments are shown in [] brackets):

```
$ docker run --rm deploy-openstack
usage: deploy-and-configure.py [-h]
                               --vcenter VCENTER
                               --vcenter_password VCENTER_PASSWORD
                               --vcenter_username VCENTER_USERNAME
                               --vm_prefix VM_PREFIX
                               [--vm_cpu VM_CPU]
                               [--vm_memory VM_MEMORY]
                               [--vm_ip [VM_IP [VM_IP ...]]]
                               [--subnet SUBNET]
                               [--gateway GATEWAY]
                               [--dns [DNS [DNS ...]]]
                               --domain DOMAIN [DOMAIN ...]
                               --template TEMPLATE
                               --folder FOLDER
                               [--datastore DATASTORE]
                               [--host HOST]
                               [--resourcepool RESOURCEPOOL]
                               [--vm_username VM_USERNAME]
                               [--vm_password VM_PASSWORD]
                               [--extra_disks [EXTRA_DISKS [EXTRA_DISKS ...]]]


```

## Example

Pull the repo
```
$ git clone https://github.com/tssgery/deploy-and-configure
```

Build the container
```
$ cd deploy-and-configure && docker build -t deploy-and-configure .
```

Run the container with necessary arguments. The followoing example deploys two nodes at ip addresses 192.168.1.176 and 178.
```
docker run --rm deploy-and-configure \
--vcenter vcenter \
--vcenter_username administrator@vsphere.local \
--vcenter_password=password \
--vm_prefix test-vm \
--vm_ip 192.168.1.176,192.168.1.178 \
--subnet 255.255.255.0 \
--gateway 192.168.1.1 \
--dns 192.168.1.1 \
--domain mydomain.com \
--template 'Ubuntu 16.04 Devstack Template' \
--resourcepool=Resources \
--folder=Testing
```
