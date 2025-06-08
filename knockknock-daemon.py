#!/usr/bin/env python3
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

import os
from grp import getgrnam
from pwd import getpwnam
from sys import exit
from knockknock.Profiles import Profiles
from knockknock.PortOpener import PortOpener
from knockknock.DaemonConfiguration import DaemonConfiguration
from knockknock.KnockWatcher import KnockWatcher
from knockknock.LogJournald import JournalReader
from knockknock.LogFile import LogFile
import knockknock.daemonize
import knockknock.daemonize
#from knockknock.knockknock_logging import do_log       # debug

def checkPrivileges():
    if not os.geteuid() == 0:
        print('Sorry, you have to run knockknock-daemon as root.')
        exit(3)


def checkConfiguration():
    if not os.path.isdir('/etc/knockknock.d/'):
        print('/etc/knockknock.d/ does not exist.  You need to setup your profiles first...')
        exit(3)

    if not os.path.isdir('/etc/knockknock.d/profiles/'):
        print('/etc/knockknock.d/profiles/ does not exist.  You need to setup your profiles first...')
        exit(3)


def dropPrivileges():
    nobody = getpwnam('nobody')
    adm = getgrnam('adm')

    os.setgroups([adm.gr_gid])
    os.setgid(adm.gr_gid)
    os.setuid(nobody.pw_uid)


def handleFirewall(input_pipe, config):
    portOpener = PortOpener(input_pipe, config.getDelay())
    #do_log('after portOpener init')        # debug
    portOpener.waitForRequests()
    #do_log('after waitForRequests')        # debug


def handleKnocks(initprocname, output, profiles, config):
    dropPrivileges()
    # Attempt to determine logging source here (since it shouldn't require
    # elevated privileges to verify this information) based on the system
    # init process. User can specify a preference in the config file, which
    # overrides automatic detection.
    #do_log(f'initprocname: {initprocname}, config.logging: {config.logging}')      debug
    if (config.logging in ["init", "preinit"]) or (initprocname in ["init", "preinit"]):
        logSource = LogFile(config.logfile)
    elif config.logging == "systemd" or initprocname == "systemd":
        logSource = JournalReader()
    else:
        print(f'config.logging: {config.logging}, initprocname: {initprocname}')
        print('Failed to find logging source for your init system. Exiting')
        exit(3)

    portOpener = PortOpener(output, config.getDelay())
    knockWatcher = KnockWatcher(config, logSource, profiles, portOpener)

    #do_log('before starting knockWatcher.tailAndProcess')      # debug
    knockWatcher.tailAndProcess()


def main():
    initprocname = ''
    # Retrieve the system init type from /proc
    with open('/proc/1/status', 'r') as f:
        initprocname = f.readline().split()[1]
    #do_log(f'got initprocname {initprocname}')     # debug

    checkPrivileges()
    checkConfiguration()

    profiles   = Profiles('/etc/knockknock.d/profiles/')
    config     = DaemonConfiguration('/etc/knockknock.d/config')

    if profiles.isEmpty():
        print('WARNING: Running knockknock-daemon without any active profiles.')

    knockknock.daemonize.createDaemon()
    input_pipe, output_pipe = os.pipe()
    pid = os.fork()

    if pid:
        # in parent process
        os.close(input_pipe)
        handleKnocks(initprocname, os.fdopen(output_pipe, 'w'), profiles, config)
        #do_log('handleKnocks block end')       # debug
    else:
        #in child process
        os.close(output_pipe)
        handleFirewall(os.fdopen(input_pipe, 'r'), config)
        #do_log('handleFirewall block end')     # debug

if __name__ == '__main__':
    main()

