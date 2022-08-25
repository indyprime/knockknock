#!/usr/bin/env python
"""knockknock-daemon implements Moxie Marlinspike's port knocking protocol."""

__author__ = "Moxie Marlinspike"
__email__  = "moxie@thoughtcrime.org"
__license__= """
Copyright (c) 2009 Moxie Marlinspike <moxie@thoughtcrime.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

import os, sys, pwd, grp

from knockknock.Profiles import Profiles
from knockknock.PortOpener import PortOpener
from knockknock.DaemonConfiguration import DaemonConfiguration
from knockknock.KnockWatcher import KnockWatcher

import knockknock.daemonize

def checkPrivileges():
    if (not os.geteuid() == 0):
        print('Sorry, you have to run knockknock-daemon as root.')
        sys.exit(3)

def checkConfiguration():
    if (not os.path.isdir('/etc/knockknock.d/')):
        print('/etc/knockknock.d/ does not exist.  You need to setup your profiles first...')
        sys.exit(3)

    if (not os.path.isdir('/etc/knockknock.d/profiles/')):
        print('/etc/knockknock.d/profiles/ does not exist.  You need to setup your profiles first...')
        sys.exit(3)

    # Retrieve the system init type from /proc
    with open('/proc/1/status', 'r') as f:
        global initprocname
        initprocname = f.readline().split()[1]

def dropPrivileges():
    nobody = pwd.getpwnam('nobody')
    adm    = grp.getgrnam('adm')

    os.setgroups([adm.gr_gid])
    os.setgid(adm.gr_gid)
    os.setuid(nobody.pw_uid)

def handleFirewall(input, config):
    portOpener = PortOpener(input, config.getDelay())
    portOpener.waitForRequests()

def handleKnocks(output, profiles, config):
#    dropPrivileges()
    # Attempt to determine logging source here (since it shouldn't require
    # elevated privileges to verify this information) based on the system
    # init process
    if initprocname == "systemd":
        from knockknock.LogJournald import JournalReader
        logSource = JournalReader()
    elif initprocname in ["init", "preinit"]:
        from knockknock.LogFile import LogFile
        logSource = LogFile('/var/log/kern.log')
    else:
        print('Failed to find logging source for your init system. Exiting')
        sys.exit(3)
    portOpener   = PortOpener(output, config.getDelay())
    knockWatcher = KnockWatcher(config, logSource, profiles, portOpener)

    knockWatcher.tailAndProcess()

def main(argv):
    checkPrivileges()
    checkConfiguration()

    profiles   = Profiles('/etc/knockknock.d/profiles/')
    config     = DaemonConfiguration('/etc/knockknock.d/config')

    if (profiles.isEmpty()):
        print('WARNING: Running knockknock-daemon without any active profiles.')

    knockknock.daemonize.createDaemon()

    input, output = os.pipe()
    pid           = os.fork()

    if pid:
        os.close(input)
        handleKnocks(os.fdopen(output, 'w'), profiles, config)
    else:
        os.close(output)
        handleFirewall(os.fdopen(input, 'r'), config)

if __name__ == '__main__':
    main(sys.argv[1:])
