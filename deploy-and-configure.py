#!/usr/bin/env python

import atexit
import argparse
import ssl
import sys
import time

from ssh_paramiko import RemoteServer
from pyVmomi import vim, vmodl
from pyVim import connect
from pyVim.connect import Disconnect, SmartConnect

class UnableToConnectException(Exception):
    message = "Unable to connect to Server"

    def __init__(self, server):
        self.details = {
            "server": server,
        }
        super(UnableToConnectException, self).__init__(self.message, self.details)

def setup_arguments():
    parser = argparse.ArgumentParser(description='Clone and configure a VM')

    # vcenter configuration
    parser.add_argument('--vcenter', dest='VCENTER', action='store', required=True,
                        default='vcenter.aceshome.name', help='vCenter hostname/ip address')
    parser.add_argument('--vcenter_password', dest='VCENTER_PASSWORD', action='store', required=True,
                        help='vCenter password')
    parser.add_argument('--vcenter_username', dest='VCENTER_USERNAME', action='store', required=True,
                        help='vCenter username')

    # vm settings
    parser.add_argument('--vm_prefix', dest='VM_PREFIX', action='store', required=True,
                        help='VM to create/configure')
    parser.add_argument('--vm_cpu', dest='VM_CPU', action='store', required=False,
                        type=int, default=4, help='Number of virtual CPU fpr the VM')
    parser.add_argument('--vm_memory', dest='VM_MEMORY', action='store', required=False,
                        type=int, default=8, help='GB of memory for the VM')
    parser.add_argument('--vm_ip', dest='VM_IP', action='store', nargs='*',
                        help='IP address to assign to the VM, ignored if DHCP')
    parser.add_argument('--subnet', dest='SUBNET', action='store',
                        help='Subnet for the VM, ignored if DHCP')
    parser.add_argument('--gateway', dest='GATEWAY', action='store',
                        help='Gateway for the VM, ignored if DHCP')
    parser.add_argument('--dns', dest='DNS', action='store', nargs='*',
                        help='DNS servers, ignored if DHCP')
    parser.add_argument('--domain', dest='DOMAIN', action='store', nargs='+', required=True,
                        help='domain name of the VM')
    parser.add_argument('--template', dest='TEMPLATE', action='store', required=True,
                        help='Template to clone')
    parser.add_argument('--folder', dest='FOLDER', action='store', required=True,
                        help='Destination folder for the VM')
    parser.add_argument('--datastore', dest='DATASTORE', action='store', nargs='*',
                        help='Possible datastores for the VM, will use the DS with the most free space')
    parser.add_argument('--host', dest='HOST', action='store',
                        help='Destination ESXi host for the VM')
    parser.add_argument('--resourcepool', dest='RESOURCEPOOL', action='store',
                        help='Resource pool for the VM')
    parser.add_argument('--vm_username', dest='VM_USERNAME', action='store',
                        default='root', help='VM username, default is \"root\"')
    parser.add_argument('--vm_password', dest='VM_PASSWORD', action='store',
                        default='password', help='VM password, default is \"password\"')
    parser.add_argument('--extra_disks', dest='EXTRA_DISKS', action='store', nargs='*',
                        help='Space separated sizes:mountpoints for additional disks to create, specified in GB')

    # some OS settings
    parser.add_argument('--git_user', action='store', default='',
                        help='user.name for git settings')
    parser.add_argument('--git_email', action='store', default='',
                        help='user.email for git settings')
    parser.add_argument('--timeserver', action='store', default='pool.ntp.org',
                        help='NTP server')

    # testing some network changes
    parser.add_argument('--network_name', action='store',
                        help='Network to place the VM on')
    parser.add_argument('--is_VDS', action='store_true', default=False,
                        help='set to true if the network is on a VDS')

    # return the parser object
    return parser


def get_obj(content, vimtype, name):
    """
     Get the vsphere object associated with a given text name
    """
    obj = None
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for c in container.view:
        if c.name == name:
            obj = c
            break
    return obj

def get_all_objs(content, vimtype):
    """
    Get all the vsphere objects associated with a given type
    """
    obj = {}
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for c in container.view:
        obj.update({c: c.name})
    return obj


def wait_for_task(task, actionName='job', hideResult=False):
    """
    Waits and provides updates on a vSphere task
    """
    old_progress = 0

    print("Task state: "+task.info.state)
    while task.info.state == vim.TaskInfo.State.running or task.info.state == vim.TaskInfo.State.queued:
        progress = task.info.progress
        if progress is not None and progress != old_progress:
            sys.stdout.write('\r')
            sys.stdout.write("[%-50s] %d%%" % ('='*(int(progress/2)), int(progress)))
            sys.stdout.flush()
            old_progress = progress
        time.sleep(2)

    if task.info.state == vim.TaskInfo.State.error:
        print("")
        print(task.info)
        raise Exception(task.info.error)

    sys.stdout.write('\r')
    sys.stdout.write("[%-50s] %d%%" % ('='*50, 100))
    sys.stdout.flush()
    print("")

    return task.info.result

def vm_poweroff(ipaddr, username, password):
    """
    Shuts down a node, by sshing into it and running shutdown
    """
    try:
        print("Powering off %s" % ipaddr)
        node_execute_command(ipaddr, username, password,
                           'shutdown -h now', numTries=1)
        print("Allowing time for VM to shutdown")
        time.sleep(10)
    except:
        pass

    return

def vm_delete(name, si):
    """
    Delete a vm based upon it's name
    """
    try:
        # sometimes vcenter will return bad data so we will try twice
        vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)
    except:
        vm = None
        pass

    if vm is None:
        return

    if vm.runtime.powerState != 'poweredOff':
        print("Powering off VM: %s" % name)
        try:
            # it is possible that the poweroff will fail as the VM is off
            # we can ignore errors here
            task = vm.PowerOffVM_Task()
            wait_for_task(task, si)
        except:
            pass

    print("Deleting existing VM: %s" % name)
    task = vm.Destroy_Task()
    wait_for_task(task, si)


def vm_poweron(name, si):
    """
    Power on a VM based upon it's name
    """
    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)
    if vm is None:
        return

    if vm.runtime.powerState != 'poweredOn':
        print("Powering on VM: %s" % name)
        task = vm.PowerOnVM_Task()
        wait_for_task(task, si)

def sizeof_fmt(num):
    """
    Returns the human readable version of a file size

    :param num:
    :return:
    """
    for item in ['bytes', 'KB', 'MB', 'GB']:
        if num < 1024.0:
            return "%3.1f%s" % (num, item)
        num /= 1024.0
    return "%3.1f%s" % (num, 'TB')

def choose_datastore(datastores, si):
    """
    Choose a datastore from a list

    Initial implementation simply picks the datastore with the most free space
    """
    if len(datastores)==1:
        return datastores[0]

    selected_datastore_name = None
    selected_datastore_size = 0

    for ds_name in datastores:
        datastore = get_obj(si.RetrieveContent(), [vim.Datastore], ds_name)
        print("Datastore {}: {} free".format(datastore.summary.name, sizeof_fmt(datastore.summary.freeSpace)))
        if datastore.summary.freeSpace > selected_datastore_size:
            selected_datastore_name = datastore.summary.name
            selected_datastore_size = datastore.summary.freeSpace

    print("Datastore {} has the most free space".format(selected_datastore_name))
    return selected_datastore_name

def template_clone(name, vm_name, args, si):
    """
    Clone a template into a VM
    """
    print("Cloning template: %s" % name)
    template = get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)
    if template is None:
        print("Template could not be found")
        return

    # this gets a little convoluted
    if args.HOST is not None:
        # get the resource pool the the specified host, if specified
        host = get_obj(si.RetrieveContent(), [vim.ComputeResource], args.HOST)
        resource_pool = host.resourcePool
    else:
        # otherwise get the resource pool for the resource pool specified
        resource_pool = get_obj(si.RetrieveContent(), [vim.ResourcePool], args.RESOURCEPOOL)

    relocateSpec = vim.vm.RelocateSpec(pool=resource_pool)

    # if the host was specified, set it in the relocate spec
    if args.HOST is not None:
        host = get_obj(si.RetrieveContent(), [vim.HostSystem], args.HOST)
        relocateSpec.host = host
    # if the datastore was specified, set it in the relocate spec
    if args.DATASTORE is not None:
        chosen_datastore = choose_datastore(args.DATASTORE, si)
        datastore = get_obj(si.RetrieveContent(), [vim.Datastore], chosen_datastore)
        relocateSpec.datastore = datastore

    vmconf = vim.vm.ConfigSpec()
    vmconf.numCPUs = args.VM_CPU
    vmconf.memoryMB = args.VM_MEMORY * 1024

    clonespec = vim.vm.CloneSpec(powerOn=False, template=False, customization=None, location=relocateSpec)
    clonespec.config = vmconf

    folder = get_obj(si.RetrieveContent(), [vim.Folder], args.FOLDER)
    clone = template.Clone(name=vm_name, folder=folder, spec=clonespec)
    wait_for_task(clone, si)

def set_network(vm_name, args, si):
    """
    Simple method for changing network virtual machines NIC.
    """

    print("Reconfiguring the network for VM: %s" % vm_name)

    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], vm_name)
    if vm is None:
        print("Error: Unable to find VM")
        sys.exit()

    if vm.runtime.powerState != 'poweredOff':
        print("Error. The VM must be off before reconfiguring")
        sys.exit()

    try:
        # This code is for changing only one Interface. For multiple Interface
        # Iterate through a loop of network names.
        device_change = []
        for device in vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualEthernetCard):
                nicspec = vim.vm.device.VirtualDeviceSpec()
                nicspec.operation = \
                    vim.vm.device.VirtualDeviceSpec.Operation.edit
                nicspec.device = device
                nicspec.device.wakeOnLanEnabled = True

                if not args.is_VDS:
                    nicspec.device.backing = \
                        vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
                    nicspec.device.backing.network = \
                        get_obj(si.RetrieveContent(), [vim.Network], args.network_name)
                    nicspec.device.backing.deviceName = args.network_name
                else:
                    network = get_obj(si.RetrieveContent(),
                                      [vim.dvs.DistributedVirtualPortgroup],
                                      args.network_name)
                    dvs_port_connection = vim.dvs.PortConnection()
                    dvs_port_connection.portgroupKey = network.key
                    dvs_port_connection.switchUuid = \
                        network.config.distributedVirtualSwitch.uuid
                    nicspec.device.backing = \
                        vim.vm.device.VirtualEthernetCard. \
                        DistributedVirtualPortBackingInfo()
                    nicspec.device.backing.port = dvs_port_connection

                nicspec.device.connectable = \
                    vim.vm.device.VirtualDevice.ConnectInfo()
                nicspec.device.connectable.startConnected = True
                nicspec.device.connectable.allowGuestControl = True
                device_change.append(nicspec)
                break

        config_spec = vim.vm.ConfigSpec(deviceChange=device_change)
        task = vm.ReconfigVM_Task(config_spec)
        wait_for_task(task, si)
        print "Successfully changed network"

    except vmodl.MethodFault as error:
        print "Caught vmodl fault : " + error.msg
        return -1

    return 0

def vm_configure(vm_name, hostname, ip, subnet, gateway, dns, domain, si):
    """
    Configure a VM, requires open-vm-tools to be installed
    """
    print("Reconfiguring the VM: %s" % vm_name)

    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], vm_name)
    if vm is None:
        print("Error: Unable to find VM")
        sys.exit()

    if vm.runtime.powerState != 'poweredOff':
        print("Error. The VM must be off before reconfiguring")
        sys.exit()

    adaptermap = vim.vm.customization.AdapterMapping()
    adaptermap.adapter = vim.vm.customization.IPSettings()
    globalip = vim.vm.customization.GlobalIPSettings()

    """Static IP Configuration"""
    adaptermap.adapter.ip = vim.vm.customization.FixedIp()
    adaptermap.adapter.ip.ipAddress = ip
    adaptermap.adapter.subnetMask = subnet
    adaptermap.adapter.gateway = gateway

    globalip.dnsServerList = dns
    globalip.dnsSuffixList = domain

    # set the local domain to the first one in the list
    adaptermap.adapter.dnsDomain = domain[0]

    # For Linux . For windows follow sysprep
    ident = vim.vm.customization.LinuxPrep(domain=domain[0],
                                           hostName=vim.vm.customization.FixedName(name=hostname))

    customspec = vim.vm.customization.Specification()
    # For only one adapter
    customspec.identity = ident
    customspec.nicSettingMap = [adaptermap]
    customspec.globalIPSettings = globalip

    task = vm.Customize(spec=customspec)

    # Wait for Network Reconfigure to complete
    wait_for_task(task, si)

def add_disk(vm_name, si, disk_size, disk_type = 'thin'):

    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], vm_name)
    if vm is None:
        print("Error: Unable to find VM")
        sys.exit()

    if vm.runtime.powerState != 'poweredOff':
        print("Error. The VM must be off before reconfiguring")
        sys.exit()

    spec = vim.vm.ConfigSpec()
    # get all disks on a VM, set unit_number to the next available
    unit_number = 0
    for dev in vm.config.hardware.device:
        if hasattr(dev.backing, 'fileName'):
            unit_number = int(dev.unitNumber) + 1
            # unit_number 7 reserved for scsi controller
            if unit_number == 7:
                unit_number += 1
            if unit_number >= 16:
                print "we don't support this many disks"
                return
        if isinstance(dev, vim.vm.device.VirtualSCSIController):
            controller = dev
    # add disk here
    dev_changes = []
    new_disk_kb = int(disk_size) * 1024 * 1024
    disk_spec = vim.vm.device.VirtualDeviceSpec()
    disk_spec.fileOperation = "create"
    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    disk_spec.device = vim.vm.device.VirtualDisk()
    disk_spec.device.backing = \
        vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
    if disk_type == 'thin':
        disk_spec.device.backing.thinProvisioned = True
    disk_spec.device.backing.diskMode = 'persistent'
    disk_spec.device.unitNumber = unit_number
    disk_spec.device.capacityInKB = new_disk_kb
    disk_spec.device.controllerKey = controller.key
    dev_changes.append(disk_spec)
    spec.deviceChange = dev_changes
    task = vm.ReconfigVM_Task(spec=spec)
    # Wait for Disk Reconfigure to complete
    wait_for_task(task, si)
    scsiid="{}:{}:0".format(controller.busNumber, unit_number)
    print "%sGB disk added to %s as %s" % (disk_size, vm.config.name, scsiid)
    return scsiid

def vm_add_disks(vm_name, disks, si):
    """
    Add additional disks if requested
    """
    if disks is None:
        return None

    added_disks = []

    print("Adding Disks")
    for d in disks:
        # the disks will come in the form of size:mountpoint
        # with the [:mountpoint] being optional
        disk_info = d.split(":")
        disk = add_disk(vm_name, si, disk_info[0], 'thin')
        if (len(disk_info) > 1):
            added_disks.append("{}|{}".format(disk, disk_info[1]))
        else:
            added_disks.append(disk)

    return added_disks

def vm_create_mount_filesystem(ipaddr, username, password, device, mount):
    # we will create one big partitioon on the disk
    partition = device+"1"
    _commands = []
    _commands.append("echo \";\" | sfdisk {}".format(device))
    _commands.append("mkfs {}".format(partition))
    _commands.append("if [ ! -d {} ]; then mkdir -p {}; fi".format(mount, mount))
    _commands.append("mount {} {}".format(partition, mount))
    for cmd in _commands:
        node_execute_command(ipaddr, username, password, cmd)

    command="blkid -o value -s UUID {}".format(partition)
    uuid = node_execute_command(ipaddr, username, password, command)
    command="echo \"UUID={} {} ext4 defaults 0 0 \" >> /etc/fstab".format(uuid, mount)
    node_execute_command(ipaddr, username, password, command)
    return

def vm_process_disks(ipaddr, username, password, added_disks):
    """
    Add additional disks if requested
    """
    if added_disks is None:
        return

    node_execute_command(ipaddr, username, password, 'apt-get install -y lsscsi || yum install -y lsscsi || zypper install -y lsscsi')

    for d in added_disks:
        # the disks will come in the form of size:mountpoint
        # with the [:mountpoint] being optional
        disk = d.split("|")
        # get the device name
        command = "lsscsi | grep :{} | awk '{{print $NF}}'".format(disk[0])
        device = node_execute_command(ipaddr, username, password, command)
        if device is None:
            print("error trying to find device name for scsi ID")
        else:
            device = device.strip()
            if (len(disk)>1 and len(disk[1])>0):
                print("Creating filesystem on %s, mounting at |%s|" % (device, disk[1]))
                vm_create_mount_filesystem(ipaddr,
                                           username,
                                           password,
                                           device,
                                           disk[1])
            else:
                print("Created raw device at %s" % (device))
                command = 'echo "{}" >> /etc/raw-devices'.format(device)
                node_execute_command(ipaddr, username, password, command)

def get_vmname(prefix, ipaddr):
    """
    Format a hostname based on prefix and ip address
    """
    vm_name=prefix + "-" + ipaddr
    return vm_name

def get_hostname(prefix, ipaddr):
    """
    Format a hostname based on prefix and ip address
    """
    vm_name=prefix + "-" + ipaddr
    vm_name=vm_name.replace(".", "-")
    return vm_name

def wait_until_boot_complete(ipaddr, username, password):
    """
    Check if boot is complete by checking runlevel
    """
    command = '[[ `/sbin/runlevel | cut -d " " -f 2` == 5 ]]'
    command = '/sbin/runlevel | cut -d " " -f 2'
    attempt = 0
    output = ""
    desired = "3"
    # print("Executing against %s (%s, %s)" % (ipaddr, username, password))
    while (True):
        output = node_execute_command(ipaddr,
                                      username,
                                      password,
                                      command,
                                      numTries=60)
	if output is not None:
            temp = output.split()
	    if len(temp)>0:
            	output = temp[0]
        if ( output == "3" or output == "5"):
            break
        attempt = attempt+1
        if (attempt > 30):
            raise UnableToConnectException(command)
        time.sleep(1)

    print("boot appears to be complete")


def node_execute_command(ipaddr, username, password, command, numTries=5):
    """
    Execute a command via ssh
    """
    attempt=1
    connected = False


    while (attempt<=numTries and connected==False):
        ssh = RemoteServer(None,
                           username=username,
                           password=password,
                           log_folder='/tmp',
                           server_has_dns=False)
        print("Connecting to: %s" % (ipaddr))

        try:
            connected, err = ssh.connect_server(ipaddr, ping=False)
        except Exception as e:
            print("Unable to connect. Will try again.")
            connected = False

        if connected == False:
            time.sleep(5)
            attempt = attempt + 1

    if connected == False:
        raise UnableToConnectException(ipaddr)

    print("Executing Command: %s" % (command))
    rc, stdout, stderr = ssh.execute_cmd(command, timeout=None)
    ssh.close_connection()

    stdout.strip()
    stderr.strip()

    if rc is True:
        print("%s" % stdout)

    return stdout.strip()

def setup_node(ipaddr, username, password, args):
    """
    Prepare a node

    """
    _commands=[]
    _commands.append('uptime')
    _commands.append('if [ ! -d /root/.ssh ]; then mkdir /root/.ssh; fi')
    _commands.append('yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm || true')
    # setup git
    _commands.append('apt-get install -y git || yum install -y git || zypper install -y git-core')
    if args.git_user != '':
        _commands.append('git config --global user.name "{}"'.format(args.git_user))
    if args.git_email != '':
        _commands.append('git config --global user.email "{}"'.format(args.git_email))
    _commands.append('git config --global credential.helper "cache --timeout=3600"')

    # add all the nodes to each nodes /etc/hosts file
    for ipaddress in args.VM_IP:
        if ipaddress != ipaddr:
            hostname = get_hostname(args.VM_PREFIX, ipaddress)
            command = "echo \"{0} {1} {2}.{3}\" >> /etc/hosts"
            command = command.format(ipaddress, hostname, hostname, args.DOMAIN[0])
            _commands.append(command)

    # setup the ssh config file to ignore strict keys for these nodes
    for ipaddress in args.VM_IP:
        command = "echo \"Host {} \" >> /root/.ssh/config".format(ipaddress)
        _commands.append(command)
        command = "echo \"   StrictHostKeyChecking no\" >> /root/.ssh/config"
        _commands.append(command)
        command = "echo \"   UserKnownHostsFile /dev/null\" >> /root/.ssh/config"
        _commands.append(command)
        command = "echo \"\" >> /root/.ssh/config"
        _commands.append(command)
        command = "echo \"Host {} \" >> /root/.ssh/config".format(get_hostname(args.VM_PREFIX, ipaddress))
        _commands.append(command)
        command = "echo \"   StrictHostKeyChecking no\" >> /root/.ssh/config"
        _commands.append(command)
        command = "echo \"   UserKnownHostsFile /dev/null\" >> /root/.ssh/config"
        _commands.append(command)
        command = "echo \"\" >> /root/.ssh/config"
        _commands.append(command)

    # setup ntp client
    # for ubuntu, configure the /etc/systemd/timesyncd.conf file and restart services
    ccc="if [ -f /etc/systemd/timesyncd.conf ]; then sed -i 's/#NTP.*/NTP={}/g' /etc/systemd/timesyncd.conf; systemctl restart systemd-timesyncd; fi".format(args.timeserver)
    _commands.append(ccc)
    # for centos
    ccc="yum install -y ntp || true"
    _commands.append(ccc)
    ccc="if [ -f /etc/ntp.conf ]; then sed -i 's/server/#server/g' /etc/ntp.conf; echo 'server {} iburst' >> /etc/ntp.conf; systemctl restart ntpd; fi".format(args.timeserver)
    _commands.append(ccc)

    for cmd in _commands:
        node_execute_command(ipaddr, username, password, cmd)

def setup_postconfig(ipaddr, username, password, args):
    _commands = []
    _commands.append("apt-get install -y sshpass || yum install -y sshpass || zypper install -y sshpass")
    _commands.append("ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N \"\"")
    _commands.append("cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys")
    _commands.append("chmod 0600 ~/.ssh/*")
    for ip in args.VM_IP:
        if ip != ipaddr:
            _commands.append("sshpass -p {} scp -r ~/.ssh root@{}:/root".format(password, ip))
    for cmd in _commands:
        node_execute_command(ipaddr, username, password, cmd)

def main():
    """
    Main logic
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.verify_mode = ssl.CERT_NONE

    parser = setup_arguments()
    args = parser.parse_args()

    si = None

    try:
        print("Trying to connect to vCenter: %s" % args.VCENTER)
        si = connect.Connect(args.VCENTER, 443, args.VCENTER_USERNAME, args.VCENTER_PASSWORD, sslContext=context)
    except IOError as e:
        pass
        atexit.register(Disconnect, si)

    print("Connected to %s" % args.VCENTER)

    print("Deleting any existing VMs")
    for ipaddress in args.VM_IP:
        vm_name=get_vmname(args.VM_PREFIX, ipaddress)
        print("=> Looking for and deleting %s" % vm_name)
        # delete existing vm
        vm_delete(vm_name, si)

    print("Trying to cleanly shut all nodes down")
    for ipaddress in args.VM_IP:
        print("=> Shutting down %s" % ipaddress)
        vm_poweroff(ipaddress, args.VM_USERNAME, args.VM_PASSWORD)

    print("Cloning the template to new VMs")
    for ipaddress in args.VM_IP:
        print("Working on %s" % ipaddress)
        # work on the services VM
        vm_name=get_vmname(args.VM_PREFIX, ipaddress)
        vm_host=get_hostname(args.VM_PREFIX, ipaddress)
        # try to clone
        template_clone(args.TEMPLATE, vm_name, args, si)

        set_network(vm_name, args, si)

        # configure the vm
        vm_configure(vm_name,
                     vm_host,
                     ipaddress,
                     args.SUBNET,
                     args.GATEWAY,
                     args.DNS,
                     args.DOMAIN,
                     si)

        # add any additional disks requested
        added = vm_add_disks(vm_name, args.EXTRA_DISKS, si)

        # power it on
        vm_poweron(vm_name, si)

        wait_until_boot_complete(ipaddress,
                                 args.VM_USERNAME,
                                 args.VM_PASSWORD)

        # create any filesystems on additional disks
        vm_process_disks(ipaddress,
                         args.VM_USERNAME,
                         args.VM_PASSWORD,
                         added)

    for ipaddress in args.VM_IP:
        # perform some post clone setup
        setup_node(ipaddress,
                   args.VM_USERNAME,
                   args.VM_PASSWORD,
                   args)

    setup_postconfig(args.VM_IP[0], args.VM_USERNAME, args.VM_PASSWORD, args)

# Start program
if __name__ == "__main__":
    main()
