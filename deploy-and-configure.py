#!/usr/bin/env python

import atexit
import argparse
import sys
import time
import ssl
from ssh import ssh

from pyVmomi import vim, vmodl
from pyVim import connect
from pyVim.connect import Disconnect, SmartConnect

class CommandFailedException(Exception):
    def __init__(self, command):
        Exception.__init__(self, command)

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
    parser.add_argument('--datastore', dest='DATASTORE', action='store',
                        help='Destination datastore for the VM')
    parser.add_argument('--host', dest='HOST', action='store',
                        help='Destination ESXi host for the VM')
    parser.add_argument('--resourcepool', dest='RESOURCEPOOL', action='store',
                        help='Resource pool for the VM')
    parser.add_argument('--vm_username', dest='VM_USERNAME', action='store',
                        default='root', help='VM username, default is \"root\"')
    parser.add_argument('--vm_password', dest='VM_PASSWORD', action='store',
                        default='password', help='VM password, default is \"password\"')

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
                           'shutdown -h now', numTries=2)
    except:
        pass

    return

def vm_delete(name, si):
    """
    Delete a vm based upon it's name
    """
    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)
    if vm is None:
        return

    if vm.runtime.powerState != 'poweredOff':
        print("Powering off VM: %s" % name)
        task = vm.PowerOffVM_Task()
        wait_for_task(task, si)

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
        datastore = get_obj(si.RetrieveContent(), [vim.Datastore], args.DATASTORE)
        relocateSpec.datastore = datastore

    vmconf = vim.vm.ConfigSpec()
    vmconf.numCPUs = args.VM_CPU
    vmconf.memoryMB = args.VM_MEMORY * 1024

    clonespec = vim.vm.CloneSpec(powerOn=False, template=False, customization=None, location=relocateSpec)
    clonespec.config = vmconf

    folder = get_obj(si.RetrieveContent(), [vim.Folder], args.FOLDER)
    clone = template.Clone(name=vm_name, folder=folder, spec=clonespec)
    wait_for_task(clone, si)

def vm_configure(vm_name, ip, subnet, gateway, dns, domain, si):
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
                                           hostName=vim.vm.customization.FixedName(name=vm_name))

    customspec = vim.vm.customization.Specification()
    # For only one adapter
    customspec.identity = ident
    customspec.nicSettingMap = [adaptermap]
    customspec.globalIPSettings = globalip

    task = vm.Customize(spec=customspec)

    # Wait for Network Reconfigure to complete
    wait_for_task(task, si)

def get_hostname(prefix, ipaddr):
    """
    Format a hostname based on prefix and ip address
    """
    vm_name=prefix + "-" + ipaddr
    vm_name=vm_name.replace(".", "-")
    return vm_name

def node_execute_command(ipaddr, username, password, command, numTries=60):
    """
    Execute a command via ssh
    """
    print("Executing Command against %s: %s" % (ipaddr, command))
    connection = ssh(ipaddr, username, password, numTries=numTries)
    rc, output = connection.sendCommand(command, showoutput=True)
    if rc is not 0:
        print("error running: [%s] %s" % (ipaddr, command))
        raise CommandFailedException(command)
    return output

def setup_node(ipaddr, username, password, args):
    """
    Prepare a node

    """
    _commands=[]
    _commands.append('uptime')
    _commands.append('( apt-get update && apt-get install -y git ) || yum install -y git')

    for cmd in _commands:
        node_execute_command(ipaddr, username, password, cmd)

    # add all the nodes to each nodes /etc/hosts file
    for ipaddress in args.VM_IP:
        if ipaddress != ipaddr:
            hostname = get_hostname(args.VM_PREFIX, ipaddress)
            command = "echo \"{0} {1} {2}.{3}\" >> /etc/hosts"
            command = command.format(ipaddress, hostname, hostname, args.DOMAIN[0])
            node_execute_command(ipaddr, username, password, command)

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

    for ipaddress in args.VM_IP:
        print("Working on %s" % ipaddress)
        # work on the services VM
        vm_name=get_hostname(args.VM_PREFIX, ipaddress)

        vm_poweroff(ipaddress, args.VM_USERNAME, args.VM_PASSWORD)

        # delete existing vm
        vm_delete(vm_name, si)

        # try to clone
        template_clone(args.TEMPLATE, vm_name, args, si)

        # configure the vm
        vm_configure(vm_name,
                    ipaddress,
                    args.SUBNET,
                    args.GATEWAY,
                    args.DNS,
                    args.DOMAIN,
                    si)

        # power it on
        vm_poweron(vm_name, si)

    # just a short sleep here. This allows the VM to get started booting
    time.sleep(60)

    for ipaddress in args.VM_IP:
        # perform some post clone setup
        setup_node(ipaddress,
                   args.VM_USERNAME,
                   args.VM_PASSWORD,
                   args)

# Start program
if __name__ == "__main__":
    main()
