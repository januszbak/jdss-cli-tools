"""
jdss-cli-tools send cli commands to JovianDSS servers

In order to create single exe file run:
C:\Python27>Scripts\pyinstaller.exe --onefile jdss-cli-tools.py
And try it:
C:\Python27>dist\jdss-cli-tools.exe -h

NOTE:
In case of error: "msvcr100.dll missing ..."
please download and install "Microsoft Visual C++ 2010 Redistributable Package (x86)": vcredist_x86.exe
"""
from __future__ import print_function
import sys
import time
import logging
import paramiko
import argparse
import collections


__author__ = 'janusz.bak@open-e.com'


# Script global variables - to be updated in parse_args():
#cli_port         = 0
#cli_password     = ''
action           = ''
delay            = 0
nodes            = []
auto_target_name = "iqn.auto.target.for.backup"        
auto_scsiid      =  time.strftime("jdss%Y%m%d%H%M")  #"1234567890123456" Starts with alpha-char becouse of Windows
auto_snap_name   =  "__auto-snap-for-external-backup__"
auto_clone_name  =  "_auto-clone-for-backup"


def time_stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def time_stamp_proper_syntax():
    return time.strftime("_%Y-%m-%d_%H-%M-%S")


def print_with_timestamp(msg):
    print('{}  {}'.format(time_stamp(), msg))


def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if 0 <= b <= 255]
        return len(host_bytes) == len(valid) == 4
    except:
        return False


def patch_crypto_be_discovery():
    """
    Monkey patches cryptography's backend detection.
    Objective: support pyinstaller freezing.
    """

    from cryptography.hazmat import backends

    try:
        from cryptography.hazmat.backends.commoncrypto.backend import \
            backend as be_cc
    except ImportError:
        be_cc = None

    try:
        from cryptography.hazmat.backends.openssl.backend import \
            backend as be_ossl
    except ImportError:
        be_ossl = None

    backends._available_backends_list = [
        be for be in (be_cc, be_ossl) if be is not None
    ]


def get_args():

    parser = argparse.ArgumentParser(
        prog='jdss-cli-tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''The %(prog)s remotely execute given command.''',
        epilog='''EXAMPLES:

 1. Create Clone of iSCSI volume and attach to iSCSI target , delete the clone created last run
      %(prog)s clone Pool-0 zvol00 192.168.0.220
 2. Shutdown three JovianDSS servers using default port but non default password
      %(prog)s --pswd password shutdown 192.168.0.220 192.168.0.221 192.168.0.222
 3. Reboot single JovianDSS server
      %(prog)s reboot 192.168.0.220
    ''')

    parser.add_argument(
        'cmd',
        metavar='command',
        choices=['clone',
                 'shutdown', 'reboot'],
        help='Available commands:  %(choices)s.'
    )
    parser.add_argument(
        'pool',
        metavar='pool-name',
        help='Enter pool name'
    )
    parser.add_argument(
        'zvol',
        metavar='zvol-name',
        help='Enter zvol name'
    )
    parser.add_argument(
        'ip',
        metavar='jdss-ip-addr',
        nargs='+',
        help='Enter nodes IP(s)'
    )
    parser.add_argument(
        '--pswd',
        metavar='password',
        default='admin',
        help='Administrator password, default=admin'
    )
    parser.add_argument(
        '--port',
        metavar='port',
        default=22223,
        type=int,
        help='CLI/API SSH port, default=22223'
    )
    parser.add_argument(
        '--delay',
        metavar='seconds',
        default=30,
        type=int,
        help='User defined reboot/shutdown delay in seconds, default=30'
    )

    # testing argv
    # sys.argv = sys.argv + \
    # ' create-vg00 192.168.0.220 192.168.0.80 192.168.0.81 '.split()
    # testing argv

    args = parser.parse_args()

    global cli_port, cli_password, action, pool, zvol, delay, nodes

    cli_port = args.port
    cli_password = args.pswd
    action = args.cmd
    pool = args.pool
    zvol = args.zvol
    delay = args.delay
    nodes = args.ip

    # validate ip-addr
    for ip in nodes :
        if not valid_ip(ip) :
            print( 'IP address {} is invalid'.format(ip))
            sys.exit(1)

    # detect doubles
    doubles = [ip for ip, c in collections.Counter(nodes).items() if c > 1]
    if doubles:
        print( 'Double IP address: {}'.format(', '.join(doubles)))
        sys.exit(1)

    # validate port
    if not 1024 <= args.port <= 65535:
        print( 'Port {} is out of allowed range 1024..65535'.format(port))
        sys.exit(1)


def send_cli_via_ssh(node_ip_address, command):

    repeat = 100
    counter = 1

    logging.getLogger("paramiko").setLevel(logging.WARNING)

    while True:

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                node_ip_address,
                port=cli_port,
                username='cli',
                password= cli_password
            )
            break
        except paramiko.AuthenticationException:
            print_with_timestamp( 'Authentication failed: {}'.format(node_ip_address))
            sys.exit(1)
        except:
            print_with_timestamp( 'Waiting for: {}'.format(node_ip_address))
            counter += 1
            time.sleep(5)

        # Connection timed out
        if counter == repeat:
            print_with_timestamp( 'Connection timed out: {}'.format(node_ip_address))
            sys.exit(1)

    stdin, stdout, stderr = ssh.exec_command(command)
    output_from_node = stdout.read().strip()
    ssh.close()

    return output_from_node


def display_delay(msg):
    for sec in range(delay, 0, -1) :
        print( '{} in {:>2} seconds \r'.format(msg,sec))
        time.sleep(1)


def shutdown_nodes():
    display_delay('Shutdown')
    for node in nodes:
        send_cli_via_ssh(node, 'shutdown')
        print_with_timestamp( 'Shutdown: {}'.format(node))


def reboot_nodes() :
    display_delay('Reboot')
    for node in nodes:
        send_cli_via_ssh(node, 'reboot')
        print_with_timestamp( 'Reboot: {}'.format(node))


def wait_for_nodes():

    for node in nodes :
        if 'Available commands:' in send_cli_via_ssh(node, 'help'):
            print_with_timestamp( 'Node {} is running.'.format(node))
        else:
            print_with_timestamp( 'Node {} is NOT available.'.format(node))


def check_if_pool_zvol_exist():
    for node in nodes:
        pools = send_cli_via_ssh(node, 'get_pools').split()
        if pool not in pools:
            print_with_timestamp( 'Pool: {} does not exist'.format(pool))
            sys.exit(1)
        zvols = send_cli_via_ssh(node, 'get_volumes_for_given_pool --pool={}'.format(pool)).split()
        if zvol not in zvols:
            print_with_timestamp( 'zvol: {} does not exist'.format(zvol))
            sys.exit(1)



def make_clone_and_export():
    
        check_if_pool_zvol_exist()

        DELETE =        'delete_snapshot --pool={} --volume={} --snapshot={} --recursively-children --recursively-dependents --force-umount'
        CREATE_SNAP =   'create_snapshot --pool={} --volume={} --snapshot={}'
        CREATE_CLONE =  'create_clone_for_given_snapshot --pool={} --volume={} --snapshot={} --clone={}'
        CREATE_TARGET = 'create_iscsi_target --pool={} --target={}'
        ATTACH =        'attach_volume_to_iscsi_target --pool={} --volume={} --target={} --scsiid={} --lun=0 --mode=rw'

        snap = auto_snap_name

        for node in nodes:
            # DELETE PREVIOUS SNAP & CLONE
            send_cli_via_ssh(node, DELETE.format(pool,zvol,snap))
            # CREATE SNAP
            send_cli_via_ssh(node, CREATE_SNAP.format(pool,zvol,snap))
            # CREATE CLONE
            stamp = time_stamp_proper_syntax()
            clone = zvol + auto_clone_name + stamp
            send_cli_via_ssh(node, CREATE_CLONE.format(pool,zvol,snap,clone))
            # CREATE TARGET
            target = '{}.{}.{}'.format(auto_target_name,pool,zvol).lower()
            send_cli_via_ssh(node, CREATE_TARGET.format(pool, target))
            # ATTACH TARGET
            output = send_cli_via_ssh(node, ATTACH.format(pool,clone,target,auto_scsiid))
            if 'successfully attached' in output:
                print_with_timestamp("Clone of {}/{} has been successfully attached to target.".format(pool,zvol))
                print("\n\tTarget:\t{}".format(target))
                print("\tClone:\t{}\n".format(clone))
            else:
                print_with_timestamp( 'Error: Attach to target FAILED')
                sys.exit(1)
           

def main() :

    get_args()

    wait_for_nodes()

    if action == 'clone':
        make_clone_and_export()
    elif action == 'shutdown':
        shutdown_nodes()
    elif action == 'reboot':
        reboot_nodes()


if __name__ == '__main__':

    patch_crypto_be_discovery()

    try:
        main()
    except KeyboardInterrupt:
        print_with_timestamp( 'Interrupted             ')
        sys.exit(0)
