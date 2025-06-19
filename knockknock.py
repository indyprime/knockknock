#!/usr/bin/env python3
__author__ = "Moxie Marlinspike"
__email__  = "moxie@thoughtcrime.org"
__license__= """
Copyright (c) 2009 Moxie Marlinspike <moxie@thoughtcrime.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

--------
Mods to replace hping3 with scapy code, and update to Python 3.*
Copyright (c) 2019, 2025 Indy <fireballiso@yahoo.com>

"""

from os import getuid, path
from sys import exit
from struct import pack, unpack
from argparse import ArgumentParser
from scapy.all import IPv6, IP, TCP, send

from knockknock.Profile import Profile
from knockknock.AddressType import isIPv6
from socket import getaddrinfo, IPPROTO_UDP
#from knockknock.knockknock_logging import do_log       # debug

def parseArguments():
    parser = ArgumentParser(
        prog='knockknock.py',
        description='client to send port knock request to server',
    )

    parser.add_argument('-p', '--portToOpen', type=int, required=True, help='port to open on the server')
    parser.add_argument('-s', '--sourceIP', type=str, help='(optional) specify source IP address from '
        'which to send the knock request')
    parser.add_argument('-d', '--destinationIP', type=str, help='(optional) specify destination address ' +
        'to which to send the knock request. If specified, the host parameter will not be resolved to get the server ' +
        'address')
    parser.add_argument('host', type=str, help='server host name (or with -d, just a profile name)')

    return parser.parse_args()


def getProfile(host):
    homedir = path.expanduser('~')

    if not path.isdir(homedir + '/.knockknock/'):
        print('Error: you need to setup your profiles in ' + homedir + '/.knockknock/')
        exit(2)

    if not path.isdir(homedir + '/.knockknock/' + host):
        print('Error: profile for host ' + host + ' not found at ' + homedir + '/.knockknock/' + host)
        exit(2)

    return Profile(homedir + '/.knockknock/' + host)


def verifyPermissions():
    if getuid() != 0:
        print('Sorry, you must be root to run this.')
        exit(2)


def lookupHost(host):
    hosts = getaddrinfo(host, None, proto=IPPROTO_UDP)
    addrs = list()

    for i in range(len(hosts)):
        addrs.append(hosts[i][4][0])

    return addrs


def chooseIP(hosts, whichAddr):
    for i in range(len(hosts)):
        print(f'{i} ... {hosts[i]}')

    choice = -1
    while (choice < 0) or (choice > len(hosts) - 1):
        choice = input(f'{whichAddr} address to use (0-{len(hosts)-1}): ')
        try:
            choice = int(choice)
        except Exception as E:
            choice = -1
            print(f'Error: {E}')

    return choice


def main(args):
    verifyPermissions()

    profile = getProfile(args.host)
    port = pack('!H', args.portToOpen)
    packetData = profile.encrypt(port)
    knockPort = profile.getKnockPort()

    idField, seqField, ackField, winField = unpack('!HIIH', packetData)

    if not args.destinationIP:
        dstList = lookupHost(args.host)
        if len(dstList) == 1:
            args.destinationIP = dstList[0]
        else:
            args.destinationIP = dstList[chooseIP(dstList, 'destination')]

    #do_log(f'port: {args.portToOpen}, profile: {args.host}, src_ip: {src_ip}, dst_ip: {dst_ip}')      # debug

    if isIPv6(args.destinationIP):
        # IPv6
        ip = IPv6(dst = args.destinationIP, fl = idField)
    else:
        # IPv4
        ip = IP(dst = args.destinationIP, id = idField)

    if args.sourceIP:
        ip.src = args.sourceIP

    # uncomment for debugging
    #print(f'dst={dst_ip}, id={idField}')
    #print(f'sport={sport},knockPort={int(knockPort)},seq={seqField},window={winField},ack={ackField}')
    #print(f'knockPort={knockPort},seq={seqField},window={winField},ack={ackField}')
    try:
        syn = TCP(dport=int(knockPort), flags='S', seq=seqField, window=winField, ack=ackField)
        send(ip/syn, verbose=False)

        print(f'Knock sent from {ip.src} to {ip.dst}, TCP port {syn.dport}.')

    except OSError:
        exit(3)


if __name__ == '__main__':
    opts = parseArguments()
    main(opts)
