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
    parser.add_argument('--vm_prefix', dest='VM_PREFIX', action='store', required=True,
                        help='VM to create/configure')
    parser.add_argument('--vm_cpu', dest='VM_CPU', action='store', required=False,
                        type=int, default=4, help='Number of virtual CPU fpr the VM')
    parser.add_argument('--vm_memory', dest='VM_MEMORY', action='store', required=False,
                        type=int, default=8, help='GB of memory for the VM')
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
    parser.add_argument('--vm_compute_ips', dest='VM_COMPUTE', action='store',
                        help='IP address of nodes to setup as compute only (comma seperated)')

    # cinder and openstack arguments
    parser.add_argument('--openstack_release', dest='OPENSTACK_RELEASE', action='store',
                        default='master',
                        help='OpenStack Release. Default is  \"master\"')
    parser.add_argument('--cinder_repo', dest='CINDER_REPO', action='store',
                        default='http://git.openstack.org/openstack/cinder',
                        help='Cinder GIT repo, default is \"http://git.openstack.org/openstack/cinder\"')
    parser.add_argument('--cinder_branch', dest='CINDER_BRANCH', action='store',
                        help='Cinder branch, default is whatever branch is used for \"openstack_release\"')
    parser.add_argument('--tox', dest='TOX', action='store_true',
                        help='If provided, run tox [after starting Devstack, if applicable]')
    parser.add_argument('--tempest_cinder', dest='TEMPEST_CINDER', action='store_true',
                        help='If provided, run Cinder tempest tests [implies starting DevStack]')
    parser.add_argument('--tempest_nova', dest='TEMPEST_NOVA', action='store_true',
                        help='If provided, run Nova tempest tests [implies starting DevStack]')
    parser.add_argument('--devstack', dest='DEVSTACK', action='store_true',
                        help='If provided, start devstack')
    parser.add_argument('--nova_repo', dest='NOVA_REPO', action='store',
                        default='http://git.openstack.org/openstack/nova',
                        help='Nova GIT repo, default is \"http://git.openstack.org/openstack/nova\"')
    parser.add_argument('--nova_branch', dest='NOVA_BRANCH', action='store',
                        help='Nova branch, default is whatever branch is used for \"openstack_release\"')
    parser.add_argument('--ephemeral', dest='EPHEMERAL', action='store_true',
                        help='If provided, sets up Nova to use ephemeral disks on ScaleIO')

    # scaleio settings, used by cinder
    parser.add_argument('--sio_username', dest='SIO_USERNAME', action='store',
                        default='admin', help='SIO Username, default is \"admin\"')
    parser.add_argument('--sio_password', dest='SIO_PASSWORD', action='store',
                        default='Scaleio123', help='SIO Password, default is \"Scaleio123\"')
    parser.add_argument('--cinder_sio_gateway', dest='CINDER_SIO_GATEWAY', action='store', required=True,
                        help='SIO Gateway address')
    parser.add_argument('--cinder_sio_pd', dest='CINDER_SIO_PD', action='store',
                        default='default', help='SIO Protection Domain, default is \"default\"')
    parser.add_argument('--cinder_sio_sp', dest='CINDER_SIO_SP', action='store',
                        default='default', help='SIO Storage Pool, default is \"default\"')
    parser.add_argument('--cinder_sio_mdm_ips', dest='CINDER_SIO_MDM_IPS', action='store', required=True,
                        help='SIO MDM IP addresses (comma delimted)')


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


def template_clone(name, vm_name, args, si):
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
    vm = get_obj(si.RetrieveContent(), [vim.VirtualMachine], vm_name)
    if vm is None:
        return

    if vm.runtime.powerState != 'poweredOff':
        print("Error. The VM must be off before reconfiguring")
        sys.exit()

    adaptermap = vim.vm.customization.AdapterMapping()
    globalip = vim.vm.customization.GlobalIPSettings()
    adaptermap.adapter = vim.vm.customization.IPSettings()
    globalip = vim.vm.customization.GlobalIPSettings()

    """Static IP Configuration"""
    adaptermap.adapter.ip = vim.vm.customization.FixedIp()
    adaptermap.adapter.ip.ipAddress = ip
    adaptermap.adapter.subnetMask = subnet
    adaptermap.adapter.gateway = gateway
    globalip.dnsServerList = dns
    globalip.dnsSuffixList = domain

    adaptermap.adapter.dnsDomain = domain

    # For Linux . For windows follow sysprep
    ident = vim.vm.customization.LinuxPrep(domain=domain,
                                           hostName=vim.vm.customization.FixedName(name=vm_name))

    customspec = vim.vm.customization.Specification()
    # For only one adapter
    customspec.identity = ident
    customspec.nicSettingMap = [adaptermap]
    customspec.globalIPSettings = globalip

    print("Reconfiguring the VM: %s" % vm_name)
    task = vm.Customize(spec=customspec)

    # Wait for Network Reconfigure to complete
    wait_for_task(task, si)


def vm_execute_command(ipaddr, username, password, command):
    print("Executing Command against %s: %s" % (ipaddr, command))
    connection = ssh(ipaddr, username, password)
    output = connection.sendCommand(command, showoutput=True)
    return


def setup_devstack(ipaddr, username, password, args, services_ip):
    # wait for the ipaddr to become available...
    vm_execute_command(ipaddr, username, password, 'uptime')

    # this is kind of ugly, but lets take all the provided arguments
    # and build them into environment variables that can be interpreted
    # remotely
    _all_env = ""
    for k in vars(args):
        if (getattr(args,k)) is not None:
            # print("export "+k+"=\""+str(getattr(args, k))+"\";")
            _all_env = _all_env + "export "+k+"=\""+str(getattr(args, k))+"\"\n"

    # setup some things needed for devstack and/or tox
    command = ("apt-get update; "
               "apt-get install -y python-pip python-gdbm; "
               "apt-get install -y build-essential libpg-dev python3-dev virtualenv;"
               "apt-get install -y git")
    vm_execute_command(ipaddr, username, password, command)

    vm_execute_command(ipaddr, username, password,
                       'cd /; mkdir git; chmod -R 777 /git')
    vm_execute_command(ipaddr, username, password,
                       'cd /git; git clone https://github.com/eric-young/devstack-tools.git')
    vm_execute_command(ipaddr, username, password,
                       'echo \''+_all_env+'\' | sort > /git/devstack.environment')
    # for setting up devstack, only the first node gets services
    # subsequent nodes get compute only
    # we check this with the 'services_ip' argument:
    #      If ipaddr==services_ip, then we are settng up the services
    command = ("cd /git/devstack-tools; source /git/devstack.environment; "
               "bin/setup-devstack " + ipaddr + " ")
    if ( ipaddr != services_ip ):
        command = command + services_ip
    vm_execute_command(ipaddr, username, password, command)

    if args.EPHEMERAL:
        # note, installing with pip only works on Pike+
        # we need to clone https://github.com/codedellemc/python-scaleioclient
        # checkout the newton branch, and run python setup.py install
        print('Moved setup of ephemeral requirements to setup_devstack')
        #vm_execute_command(ipaddr, username, password,
        #                   '''cd /git;
        #                   git clone https://github.com/codedellemc/python-scaleioclient -b newton
        #                   cd python-scaleioclient
        #                   python setup.py install''')
        #vm_execute_command(ipaddr, username, password,
        #                   'sed -i -e "s|## images_type=sio|images_type=sio|g" /git/devstack/local.conf')


def run_postinstall(ipaddr, args):
    if args.DEVSTACK or args.TEMPEST_CINDER or args.TEMPEST_NOVA:
        vm_execute_command(ipaddr, 'stack', 'stack',
                           'cd /git/devstack; ./stack.sh')

def run_postinstall_services_only(ipaddr, args):
    if args.TOX:
        vm_execute_command(ipaddr, 'stack', 'stack',
                 '/git/devstack-tools/bin/run-tox')

    if args.TEMPEST_CINDER:
        vm_execute_command(ipaddr, 'stack', 'stack',
                 '''source /git/devstack/openrc admin && '''
                 '''/git/devstack-tools/bin/run-tempest-cinder''')

    if args.TEMPEST_NOVA:
        vm_execute_command(ipaddr, 'stack', 'stack',
                 '''source /git/devstack/openrc admin && '''
                 '''/git/devstack-tools/bin/run-tempest-nova''')

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

    all_ip_addresses = args.VM_IP.split(",")
    for ipaddress in all_ip_addresses:
        # work on the services VM
        vm_name=args.VM_PREFIX + "-" + ipaddress
        vm_name=vm_name.replace(".", "-")

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

    all_ip_addresses = args.VM_IP.split(",")
    for i, ipaddress in enumerate(all_ip_addresses):
        # setup devstack on these VMs
        # note that the fist ipaddress will get the services
        # subsequent ipaddresses will be compute only
        setup_devstack(ipaddress,
                       args.VM_USERNAME,
                       args.VM_PASSWORD,
                       args,
                       all_ip_addresses[0])

    # run anything that needs to be run on all hosts
    for i, ipaddress in enumerate(all_ip_addresses):
        run_postinstall(ipaddress, args)

    # run anything that gets run on first node only
    run_postinstall_services_only(all_ip_addresses[0], args)

# Start program
if __name__ == "__main__":
    main()
