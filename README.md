# deploy-and-configure

Designed to automate setting up DevStack with ScaleIO as a backing source

This repository builds a docker container that knows how to:
* Clone a vSphere template into 1 or more Virtual Machines
* Configure the networking (static only) for these VMs
* Install the ScaleIO SDC on the nodes
* Clone the http://github.com/eric-young/devstack-tools repo to each VM
* Configure Cinder to use ScaleIO for the backing volumes
* Run the scripts within that repo to setup devstack in a myriad of ways. These ways are controlled by options passed to the container [which passes then through to the devstack-tools]

## Command Line Options

Running the container without any options will show the usage information (optional arguments are shown in [] brackets):

```
$ docker run --rm deploy-openstack
usage: deploy-and-configure.py [-h] --vcenter VCENTER --vcenter_password
                               VCENTER_PASSWORD --vcenter_username
                               VCENTER_USERNAME --vm_prefix VM_PREFIX
                               [--vm_ip VM_IP] [--subnet SUBNET]
                               [--gateway GATEWAY] [--dns [DNS [DNS ...]]]
                               --domain DOMAIN --template TEMPLATE --folder
                               FOLDER [--datastore DATASTORE] [--host HOST]
                               [--resourcepool RESOURCEPOOL]
                               [--vm_username VM_USERNAME]
                               [--vm_password VM_PASSWORD]
                               [--vm_compute_ips VM_COMPUTE]
                               [--openstack_release OPENSTACK_RELEASE]
                               [--cinder_repo CINDER_REPO]
                               [--cinder_branch CINDER_BRANCH] [--tox]
                               [--tempest_cinder] [--tempest_nova]
                               [--devstack] [--nova_repo NOVA_REPO]
                               [--nova_branch NOVA_BRANCH] [--ephemeral]
                               --cinder_sio_gateway CINDER_SIO_GATEWAY
                               [--cinder_sio_pd CINDER_SIO_PD]
                               [--cinder_sio_sp CINDER_SIO_SP]
                               --cinder_sio_mdm_ips CINDER_SIO_MDM_IPS
```

## Example

Pull the repo
```
$ git clone https://github.com/eric-young/deploy-and-configure
```

Build the container
```
$ cd deploy-openstack && docker build -t deploy-openstack .
```

Run the container with necessary arguments. The followoing example deploys a two-node devstack system from the master branch at ip addresses 192.168.1.176/178. It will then start devstack on both nodes and run the tempest tests for Cinder.
```
docker run --rm deploy-openstack \
--vcenter vcenter \
--vcenter_username administrator@vsphere.local \
--vcenter_password=password \
--vm_prefix test-devstack \
--vm_ip 192.168.1.176,192.168.1.178 \
--subnet 255.255.255.0 \
--gateway 192.168.1.1 \
--dns 192.168.1.1 \
--cinder_sio_gateway 192.168.1.221 \
--cinder_sio_mdm_ips 192.168.1.221,192.168.1.223 \
--openstack_release master \
--domain mydomain.com \
--template 'Ubuntu 16.04 Devstack Template' \
--resourcepool=Resources \
--folder=Testing \
--tempest_cinder
```
