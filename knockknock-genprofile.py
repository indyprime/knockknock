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

"""

from os import path, mkdir
from argparse import ArgumentParser
from sys import exit
from secrets import token_bytes

from knockknock.Profiles import Profiles
from knockknock.Profile  import Profile

DAEMON_DIR   = '/etc/knockknock.d/'
PROFILES_DIR = DAEMON_DIR + 'profiles/'


def parseArguments():
    parser = ArgumentParser(
        prog='knockknock-genprofile.py',
        description='Create profile for knockknock server',
    )

    parser.add_argument('profileName', type=str, help='Name of profile (can be server domain name)')
    parser.add_argument('knockPort', type=int, help='Port to which to send the knock')

    return parser.parse_args()

def checkProfile(profileName):
    if path.isdir(PROFILES_DIR + profileName):
        print('Profile already exists.  First rm ' + PROFILES_DIR + profileName + '/')
        exit(0)

def checkPortConflict(knockPort):
    if not path.isdir(PROFILES_DIR):
        return

    profiles        = Profiles(PROFILES_DIR)
    matchingProfile = profiles.getProfileForPort(knockPort)

    if matchingProfile is not None:
        print('A profile already exists for knock port: ' + str(knockPort) + ' at this location: ' + matchingProfile.getDirectory())

def createDirectory(profileName):
    if not path.isdir(DAEMON_DIR):
        mkdir(DAEMON_DIR)

    if not path.isdir(PROFILES_DIR):
        mkdir(PROFILES_DIR)

    if not path.isdir(PROFILES_DIR + profileName):
        mkdir(PROFILES_DIR + profileName)

def main(args):
    if args.knockPort < 1 or args.knockPort > 65535:
        print('knockPort must be 1-65535')
        exit(0)

    checkProfile(args.profileName)
    checkPortConflict(args.knockPort)
    createDirectory(args.profileName)

    cipherKey = token_bytes(16)
    macKey    = token_bytes(16)
    counter   = 0

    profile = Profile(PROFILES_DIR + args.profileName, cipherKey, macKey, counter, args.knockPort)
    profile.serialize()

    print('Keys successfully generated in ' + PROFILES_DIR + args.profileName)


if __name__ == '__main__':
    opts = parseArguments()
    main(opts)
