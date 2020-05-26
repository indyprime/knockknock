#!/usr/bin/env python
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
Copyright (c) 2019 Indy <fireballiso@yahoo.com>

"""

import time, os, sys
import getopt
import subprocess

from struct import *
from knockknock.Profile import Profile
from scapy.all import *
from ipaddress import IPv6Address
from knockknock.AddressType import isIPv6
from socket import getaddrinfo, IPPROTO_UDP

def usage():
    print('Usage: knockknock.py -p <portToOpen> [-s source_ip] [-d destination_ip] <host>'
        + '\t* source_ip can be optionally set, to specifically use a certain source IP'
        + '\t* destination_ip can be optionally set, to use that instead of resolving the\n'
        + '\thostname; that way, the \"host\" is only used as a profile name')
    sys.exit(2)

def parseArguments(argv):
    try:
        port = 0
        host = ''
        src_ip = ''
        dst_ip = ''
        opts, args = getopt.getopt(argv, 'h:p:s:d:')

        for opt, arg in opts:
            if opt in ('-p'):
                port = arg
            elif opt in ('-s'):
                src_ip = arg
            elif opt in ('-d'):
                dst_ip = arg
            else:
                usage()

#        if len(args) != 1:
        if len(args) < 1:
            usage()
        else:
            host = args[0]

    except getopt.GetoptError:
        usage()

    if port == 0 or host == '':
        usage()

    return (port, host, src_ip, dst_ip)

def getProfile(host):
    homedir = os.path.expanduser('~')

    if not os.path.isdir(homedir + '/.knockknock/'):
        print('Error: you need to setup your profiles in ' + homedir + '/.knockknock/')
        sys.exit(2)

    if not os.path.isdir(homedir + '/.knockknock/' + host):
        print('Error: profile for host ' + host + ' not found at ' + homedir + '/.knockknock/' + host)
        sys.exit(2)

    return Profile(homedir + '/.knockknock/' + host)

def verifyPermissions():
    if os.getuid() != 0:
        print('Sorry, you must be root to run this.')
        sys.exit(2)

def lookupHost(host):
    hosts = getaddrinfo(host, None, proto=IPPROTO_UDP)

    for i in range(len(hosts)):
        hosts[i] = hosts[i][4][0]

    return hosts

def chooseIP(hosts, whichAddr):
    for i in range(len(hosts)):
        print('{0} ... {1}'.format(i, hosts[i]))

    choice = -1
    while((choice < 0) or (choice > len(hosts)-1)):
        choice = input('{0} address to use (0-{1}):'.format(whichAddr, len(hosts)-1))
        try:
            choice = int(choice)
        except:
            choice = -1

    return choice

#another method:
#def lookupHost(host):
#    output = run(['nslookup', '-type=AAAA', 'www.yahoo.com'], capture_output=True)

def main(argv):
    (port, host, src_ip, dst_ip) = parseArguments(argv)
    verifyPermissions()

    profile      = getProfile(host)
    port         = pack('!H', int(port))
    packetData   = profile.encrypt(port)
    knockPort    = profile.getKnockPort()

    (idField, seqField, ackField, winField) = unpack('!HIIH', packetData)

    sport = random.randint(1024,65535)

    if dst_ip == '':
        dstList = lookupHost(host)
        if len(dstList) == 1:
            dst_ip = dstList[0]
        else:
            dst_ip = dstList[chooseIP(dstList, 'destination')]

    if isIPv6(dst_ip):
        # IPv6
        ip = IPv6(dst = dst_ip, fl = idField)
    else:
        # IPv4
        ip = IP(dst = dst_ip, id = idField)

    if src_ip != '':
        ip.src = src_ip
#    else:
#        srcList = getHostAddrs
#        if len(srcList) == 1:
#            src_ip = srcList[0]
#        else:
#            src_ip = srcList[chooseIP(dstList, 'source')]

    # uncomment for debugging
#    print('dst={0}, id={1}'.format(dst_ip,idField))
#    print('sport={0},dport={1},seq={2},window={3},ack={4}'.format(sport,int(knockPort),seqField,winField,ackField))

    try:
        syn=TCP(sport=sport,dport=int(knockPort),flags='S',seq=seqField,window=winField,ack=ackField)
        send(ip/syn, verbose=False)

        print('Knock sent from {0} to {1}, TCP port {2}.'.format(ip.src, ip.dst, syn.dport))

    except OSError:
        sys.exit(3)

if __name__ == '__main__':
    main(sys.argv[1:])

