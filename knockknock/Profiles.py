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

import os
from socket import gethostbyname_ex
from .Profile import Profile
#from .knockknock_logging import do_log     # debug

class Profiles:

    def __init__(self, directory):
        self.profiles = list()

        for item in os.listdir(directory):
            if os.path.isdir(os.path.join(directory, item)):
                self.profiles.append(Profile(os.path.join(directory, item)))


    def getProfileForPort(self, port):
        for profile in self.profiles:
            if int(profile.getKnockPort()) == int(port):
                return profile
        #do_log(f'no profile for port {port}')       # debug
        return None


    def getProfileForName(self, name):
        for profile in self.profiles:
            if name == profile.getName():
                return profile
        #do_log(f'no profile for name {name}')      # debug
        return None


    def getProfileForIP(self, ip):
        for profile in self.profiles:
            ips = profile.getIPAddrs()

            if ip in ips:
                return profile
        #do_log(f'no profile for IP {ip}')      # debug
        return None


    def resolveNames(self):
        for profile in self.profiles:
            name = profile.getName()
            address, alias, addrlist = gethostbyname_ex(name)

            profile.setIPAddrs(addrlist)
            #do_log(f'for name {name}, got address(es) {addrlist}')     # debug


    def isEmpty(self):
        return len(self.profiles) == 0
