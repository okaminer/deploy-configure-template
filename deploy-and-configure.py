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


def setup_arguments():
    parser = argparse.ArgumentParser(description='Clone and configure a VM')
    # vcenter configuration
    parser.add_argument('--vcenter', dest='vcenter', action='store', required=True,
                        default='vcenter.aceshome.name', help='vCenter hostname/ip address')
    parser.add_argument('--vcenter_password', dest='vcenter_password', action='store', required=True,
                        help='vCenter password')
    parser.add_argument('--vcenter_username', dest='vcenter_username', action='store', required=True,
                        help='vCenter username')
    # vm settings
    parser.add_argument('--vm_name', dest='vm_name', action='store', required=True,
                        help='VM to create/configure')
    parser.add_argument('--dhcp', dest='dhcp', action='store_true',
                        help='Configures DHCP if supplied')
    parser.add_argument('--vm_ip', dest='vm_ip', action='store',
                        help='IP address to assign to the VM, ignored if DHCP')
    parser.add_argument('--subnet', dest='subnet', action='store',
                        help='Subnet for the VM, ignored if DHCP')
    parser.add_argument('--gateway', dest='gateway', action='store',
                        help='Gateway for the VM, ignored if DHCP')
    parser.add_argument('--dns', dest='dns', action='store', nargs='*',
                        help='DNS servers, ignored if DHCP')
    parser.add_argument('--domain', dest='domain', action='store', required=True,
                        help='domain name of the VM')
    parser.add_argument('--template', dest='template', action='store', required=True,
                        help='Template to clone')
    parser.add_argument('--folder', dest='folder', action='store', required=True,
                        help='Destination folder for the VM')
    parser.add_argument('--datastore', dest='datastore', action='store',
                        help='Destination datastore for the VM')
    parser.add_argument('--host', dest='host', action='store',
                        help='Destination ESXi host for the VM')
    parser.add_argument('--resourcepool', dest='resourcepool', action='store',
                        help='Resource pool for the VM')
    parser.add_argument('--vm_username', dest='vm_username', action='store',
                        default='root', help='VM username, default is \"root\"')
    parser.add_argument('--vm_password', dest='vm_password', action='store',
                        default='password', help='VM password, default is \"password\"')
    # cinder and openstack arguments
    parser.add_argument('--openstack_release', dest='openstack_release', action='store',
                        default='master',
                        help='OpenStack Release. Default is  \"master\"')
    parser.add_argument('--cinder_repo', dest='cinder_repo', action='store',
                        default='http://git.openstack.org/openstack/cinder',
                        help='Cinder GIT repo, default is \"http://git.openstack.org/openstack/cinder\"')
    parser.add_argument('--cinder_branch', dest='cinder_branch', action='store',
                        default='master', help='Cinder branch, default is \"master\"')
    parser.add_argument('--cinder_sio_gateway', dest='cinder_sio_gateway', action='store', required=True,
                        help='SIO Gateway address')
    parser.add_argument('--cinder_sio_pd', dest='cinder_sio_pd', action='store',
                        default='default', help='SIO Protection Domain, default is \"default\"')
    parser.add_argument('--cinder_sio_sp', dest='cinder_sio_sp', action='store',
                        default='default', help='SIO Storage Pool, default is \"default\"')
    parser.add_argument('--cinder_sio_mdm_ips', dest='cinder_sio_mdm_ips', action='store', required=True,
                        help='SIO MDM IP addresses (comma delimted)')
    parser.add_argument('--tox', dest='tox', action='store_true',
                        help='If provided, run tox [after starting Devstack, if applicable]')
    parser.add_argument('--devstack', dest='devstack', action='store_true',
                        help='If provided, start devstack')

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
            # the exact output you're looking for:
            sys.stdout.write("[%-50s] %d%%" % ('='*(int(progress/2)), int(progress)))
            sys.stdout.flush()
            old_progress = progress
        time.sleep(2)

    if task.info.state == vim.TaskInfo.State.success:
        sys.stdout.write('\r')
        # the exact output you're looking for:
        sys.stdout.write("[%-50s] %d%%" % ('='*50, 100))
        print("")
    else:
        print("")
        print(task.info)
        raise Exception(task.info.error)

    print("")

    return task.info.result


def vm_delete(name, si):
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
    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)
    if vm is None:
        return

    if vm.runtime.powerState != 'poweredOn':
        print("Powering on VM: %s" % name)
        task = vm.PowerOnVM_Task()
        wait_for_task(task, si)


def template_clone(name, args, si):
    print("Cloning template: %s" % name)
    template = get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)
    if template is None:
        print("Template could not be found")
        return

    # this gets a little convoluted
    if args.host is not None:
        # get the resource pool the the specified host, if specified
        host = get_obj(si.RetrieveContent(), [vim.ComputeResource], args.host)
        resource_pool = host.resourcePool
    else:
        # otherwise get the resource pool for the resource pool specified
        resource_pool = get_obj(si.RetrieveContent(), [vim.ResourcePool], args.resourcepool)

    relocateSpec = vim.vm.RelocateSpec(pool=resource_pool)

    # if the host was specified, set it in the relocate spec
    if args.host is not None:
        host = get_obj(si.RetrieveContent(), [vim.HostSystem], args.host)
        relocateSpec.host = host
    # if the datastore was specified, set it in the relocate spec
    if args.datastore is not None:
        datastore = get_obj(si.RetrieveContent(), [vim.Datastore], args.datastore)
        relocateSpec.datastore = datastore

    clonespec = vim.vm.CloneSpec(powerOn=False, template=False, customization=None, location=relocateSpec)
    folder = get_obj(si.RetrieveContent(), [vim.Folder], args.folder)
    clone = template.Clone(name=args.vm_name, folder=folder, spec=clonespec)
    wait_for_task(clone, si)

def vm_configure(name, args, si):
    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)
    if vm is None:
        return

    if vm.runtime.powerState != 'poweredOff':
        print("Error. The VM must be off before reconfiguring")
        sys.exit()

    adaptermap = vim.vm.customization.AdapterMapping()
    globalip = vim.vm.customization.GlobalIPSettings()
    adaptermap.adapter = vim.vm.customization.IPSettings()
    globalip = vim.vm.customization.GlobalIPSettings()

    if not args.dhcp:
        """Static IP Configuration"""
        adaptermap.adapter.ip = vim.vm.customization.FixedIp()
        adaptermap.adapter.ip.ipAddress = args.vm_ip
        adaptermap.adapter.subnetMask = args.subnet
        adaptermap.adapter.gateway = args.gateway
        globalip.dnsServerList = args.dns
        globalip.dnsSuffixList = args.domain

    else:
        """DHCP Configuration"""
        adaptermap.adapter.ip = vim.vm.customization.DhcpIpGenerator()

    adaptermap.adapter.dnsDomain = args.domain

    # For Linux . For windows follow sysprep
    ident = vim.vm.customization.LinuxPrep(domain=args.domain,
                                           hostName=vim.vm.customization.FixedName(name=args.vm_name))

    customspec = vim.vm.customization.Specification()
    # For only one adapter
    customspec.identity = ident
    customspec.nicSettingMap = [adaptermap]
    customspec.globalIPSettings = globalip

    print("Reconfiguring the VM: %s" % name)
    task = vm.Customize(spec=customspec)

    # Wait for Network Reconfigure to complete
    wait_for_task(task, si)


def vm_execute_command(name, username, password, si, command):
    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], name)

    if vm is None:
        return

    print("Executing Command against %s: %s" % (vm.guest.ipAddress, command))
    connection = ssh(vm.guest.ipAddress, username, password)
    output = connection.sendCommand(command, showoutput=True)
    return


def setup_devstack(name, args, si):
    for k in vars(args):
        if (getattr(args,k)) is not None:
            print("export "+k+"="+getattr(args, str(k))

    vm_execute_command(args.vm_name, args.vm_username, args.vm_password, si,
                       'apt-get update; apt-get install git')
    # setup some things needed for devstack and/or tox
    command = ("sudo apt-get install -y python-pip python-gdbm; sudo pip install tox; "
               "sudo apt-get install -y build-essential libpg-dev python3-dev virtualenv;")
    vm_execute_command(args.vm_name, args.vm_username, args.vm_password, si, command)

    vm_execute_command(args.vm_name, args.vm_username, args.vm_password, si,
                       'cd /; mkdir git; chmod -R 777 /git')
    vm_execute_command(args.vm_name, args.vm_username, args.vm_password, si,
                       'cd /git; git clone https://github.com/tssgery/devstack-tools.git')
    vm_execute_command(args.vm_name, args.vm_username, args.vm_password, si,
                       '''cd /git/devstack-tools;
                       export OPENSTACK_RELEASE='''+args.openstack_release+''';
                       export CINDER_REPO='''+args.cinder_repo+''';
                       export CINDER_BRANCH='''+args.cinder_branch+''';
                       export MDM_IPS='''+args.cinder_sio_mdm_ips+''';
                       export PD='''+args.cinder_sio_pd+''';
                       export SP='''+args.cinder_sio_sp+''';
                       export GATEWAY='''+args.cinder_sio_gateway+''';
                       bin/setup-development-devstack''')
    vm_execute_command(args.vm_name, 'stack', 'stack', si,
                       'cd /git/devstack; cat local.conf')

    if args.devstack:
        vm_execute_command(args.vm_name, 'stack', 'stack', si,
                           'cd /git/devstack; ./stack.sh')

    if args.tox:
        cmd_vars = {'repo': args.cinder_repo,
                    'branch': args.cinder_branch,
                    'dir': '/git/cinder'}
        command = ("git clone %(repo)s -b %(branch)s %(dir)s; "
                   "cd %(dir)s; "
                   "UPPER_CONSTRAINTS_FILE=http://git.openstack.org/cgit/openstack/requirements/plain/upper-constraints.txt tox") % cmd_vars
        vm_execute_command(args.vm_name, 'stack', 'stack', si, command)


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.verify_mode = ssl.CERT_NONE

    parser = setup_arguments()
    args = parser.parse_args()

    si = None

    try:
        print("Trying to connect to vCenter: %s" % args.vcenter)
        si = connect.Connect(args.vcenter, 443, args.vcenter_username, args.vcenter_password, sslContext=context)
    except IOError as e:
        pass
        atexit.register(Disconnect, si)

    print("Connected to %s" % args.vcenter)

    # delete existing vm
    vm_delete(args.vm_name, si)

    # try to clone
    template_clone(args.template, args, si)

    # configure the vm
    vm_configure(args.vm_name, args, si)

    # power it on
    vm_poweron(args.vm_name, si)

    print("Sleeping for 5 minutes to allow VM to power on and configure itself")
    time.sleep(300)

    setup_devstack(args.vm_name, args, si)


# Start program
if __name__ == "__main__":
    main()
