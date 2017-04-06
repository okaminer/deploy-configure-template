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
    parser.add_argument('--vcenter', dest='VCENTER', action='store', required=True,
                        default='vcenter.aceshome.name', help='vCenter hostname/ip address')
    parser.add_argument('--vcenter_password', dest='VCENTER_PASSWORD', action='store', required=True,
                        help='vCenter password')
    parser.add_argument('--vcenter_username', dest='VCENTER_USERNAME', action='store', required=True,
                        help='vCenter username')
    # vm settings
    parser.add_argument('--vm_name', dest='VM_NAME', action='store', required=True,
                        help='VM to create/configure')
    parser.add_argument('--dhcp', dest='DHPC', action='store_true',
                        help='Configures DHCP if supplied')
    parser.add_argument('--vm_ip', dest='VM_IP', action='store',
                        help='IP address to assign to the VM, ignored if DHCP')
    parser.add_argument('--subnet', dest='SUBNET', action='store',
                        help='Subnet for the VM, ignored if DHCP')
    parser.add_argument('--gateway', dest='GATEWAY', action='store',
                        help='Gateway for the VM, ignored if DHCP')
    parser.add_argument('--dns', dest='DNS', action='store', nargs='*',
                        help='DNS servers, ignored if DHCP')
    parser.add_argument('--domain', dest='DOMAIN', action='store', required=True,
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
    # cinder and openstack arguments
    parser.add_argument('--openstack_release', dest='OPENSTACK_RELEASE', action='store',
                        default='master',
                        help='OpenStack Release. Default is  \"master\"')
    parser.add_argument('--cinder_repo', dest='CINDER_REPO', action='store',
                        default='http://git.openstack.org/openstack/cinder',
                        help='Cinder GIT repo, default is \"http://git.openstack.org/openstack/cinder\"')
    parser.add_argument('--cinder_branch', dest='CINDER_BRANCH', action='store',
                        default='master', help='Cinder branch, default is \"master\"')
    parser.add_argument('--cinder_sio_gateway', dest='CINDER_SIO_GATEWAY', action='store', required=True,
                        help='SIO Gateway address')
    parser.add_argument('--cinder_sio_pd', dest='CINDER_SIO_PD', action='store',
                        default='default', help='SIO Protection Domain, default is \"default\"')
    parser.add_argument('--cinder_sio_sp', dest='CINDER_SIO_SP', action='store',
                        default='default', help='SIO Storage Pool, default is \"default\"')
    parser.add_argument('--cinder_sio_mdm_ips', dest='CINDER_SIO_MDM_IPS', action='store', required=True,
                        help='SIO MDM IP addresses (comma delimted)')
    parser.add_argument('--tox', dest='TOX', action='store_true',
                        help='If provided, run tox [after starting Devstack, if applicable]')
    parser.add_argument('--devstack', dest='DEVSTACK', action='store_true',
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

    clonespec = vim.vm.CloneSpec(powerOn=False, template=False, customization=None, location=relocateSpec)
    folder = get_obj(si.RetrieveContent(), [vim.Folder], args.FOLDER)
    clone = template.Clone(name=args.VM_NAME, folder=folder, spec=clonespec)
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

    if not args.DHPC:
        """Static IP Configuration"""
        adaptermap.adapter.ip = vim.vm.customization.FixedIp()
        adaptermap.adapter.ip.ipAddress = args.VM_IP
        adaptermap.adapter.subnetMask = args.SUBNET
        adaptermap.adapter.gateway = args.GATEWAY
        globalip.dnsServerList = args.DNS
        globalip.dnsSuffixList = args.DOMAIN

    else:
        """DHCP Configuration"""
        adaptermap.adapter.ip = vim.vm.customization.DhcpIpGenerator()

    adaptermap.adapter.dnsDomain = args.DOMAIN

    # For Linux . For windows follow sysprep
    ident = vim.vm.customization.LinuxPrep(domain=args.DOMAIN,
                                           hostName=vim.vm.customization.FixedName(name=args.VM_NAME))

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
    # this is kind of ugly, but lets take all the provided arguments
    # and build them into environment variables that can be interpreted
    # remotely
    _all_env = ""
    for k in vars(args):
        if (getattr(args,k)) is not None:
            # print("export "+k+"=\""+str(getattr(args, k))+"\";")
            _all_env = _all_env + "export "+k+"=\""+str(getattr(args, k))+"\";\n"

    print (_all_env)

    vm_execute_command(args.VM_NAME, args.VM_USERNAME, args.VM_PASSWORD, si,
                       'apt-get update; apt-get install git')
    # setup some things needed for devstack and/or tox
    command = ("sudo apt-get install -y python-pip python-gdbm; sudo pip install tox; "
               "sudo apt-get install -y build-essential libpg-dev python3-dev virtualenv;")
    vm_execute_command(args.VM_NAME, args.VM_USERNAME, args.VM_PASSWORD, si, command)

    vm_execute_command(args.VM_NAME, args.VM_USERNAME, args.VM_PASSWORD, si,
                       'cd /; mkdir git; chmod -R 777 /git')
    vm_execute_command(args.VM_NAME, args.VM_USERNAME, args.VM_PASSWORD, si,
                       'cd /git; git clone https://github.com/tssgery/devstack-tools.git')
    vm_execute_command(args.VM_NAME, args.VM_USERNAME, args.VM_PASSWORD, si,
                       'echo \''+_all_env+'\' > ~/devstack.environment')                       
    vm_execute_command(args.VM_NAME, args.VM_USERNAME, args.VM_PASSWORD, si,
                       '''cd /git/devstack-tools;
                       export OPENSTACK_RELEASE='''+args.OPENSTACK_RELEASE+''';
                       export CINDER_REPO='''+args.CINDER_REPO+''';
                       export CINDER_BRANCH='''+args.CINDER_BRANCH+''';
                       export MDM_IPS='''+args.CINDER_SIO_MDM_IPS+''';
                       export PD='''+args.CINDER_SIO_PD+''';
                       export SP='''+args.CINDER_SIO_SP+''';
                       export GATEWAY='''+args.CINDER_SIO_GATEWAY+''';
                       bin/setup-development-devstack''')
    vm_execute_command(args.VM_NAME, 'stack', 'stack', si,
                       'cd /git/devstack; cat local.conf')

    if args.DEVSTACK:
        vm_execute_command(args.VM_NAME, 'stack', 'stack', si,
                           'cd /git/devstack; ./stack.sh')

    if args.TOX:
        cmd_vars = {'repo': args.CINDER_REPO,
                    'branch': args.CINDER_BRANCH,
                    'dir': '/git/cinder'}
        command = ("git clone %(repo)s -b %(branch)s %(dir)s; "
                   "cd %(dir)s; "
                   "UPPER_CONSTRAINTS_FILE=http://git.openstack.org/cgit/openstack/requirements/plain/upper-constraints.txt tox") % cmd_vars
        vm_execute_command(args.VM_NAME, 'stack', 'stack', si, command)


def main():
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

    # delete existing vm
    vm_delete(args.VM_NAME, si)

    # try to clone
    template_clone(args.TEMPLATE, args, si)

    # configure the vm
    vm_configure(args.VM_NAME, args, si)

    # power it on
    vm_poweron(args.VM_NAME, si)

    print("Sleeping for 5 minutes to allow VM to power on and configure itself")
    time.sleep(300)

    setup_devstack(args.VM_NAME, args, si)


# Start program
if __name__ == "__main__":
    main()
