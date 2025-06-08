# Copyright (c) 2009 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

from os import _exit
from subprocess import call
from syslog import syslog

from .RuleTimer import RuleTimer
from .AddressType import isIPv6
#from .knockknock_logging import do_log     # debug

class PortOpener:

    def __init__(self, stream, openDuration):
        self.stream       = stream
        self.openDuration = openDuration


    def waitForRequests(self):
        while True:
            sourceIP = self.stream.readline().rstrip('\n')
            port = self.stream.readline().rstrip('\n')

            if sourceIP == '' or port == '':
                syslog('knockknock.PortOpener: Parent process is closed.  Terminating.')
                _exit(4)

            description = 'INPUT -m limit --limit 1/minute --limit-burst 1 -m state --state NEW -p tcp -s ' + sourceIP + ' --dport ' + str(port) + ' -j ACCEPT'
            addrIsIPv6 = isIPv6(sourceIP)
            if addrIsIPv6:
                command = '/usr/sbin/ip6tables -I ' + description
            else:
                command = '/usr/sbin/iptables -I ' + description
            #do_log(f'adding iptables rule: {command}')     # debug

            command = command.split()
            call(command, shell=False)
            RuleTimer(self.openDuration, description, addrIsIPv6).start()


    def open(self, sourceIP, port):
        try:
            self.stream.write(sourceIP + '\n')
            self.stream.write(str(port) + '\n')
            self.stream.flush()
        except:
            syslog('knockknock:  Error, PortOpener process has died.  Terminating.')
            _exit(4)
