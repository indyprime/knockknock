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

import string
from struct import *

class LogEntry:

    def __init__(self, line):
        self.buildTokenMap(line)

    def buildTokenMap(self, line):
        self.tokenMap = dict()

        for token in line.split():
            index = token.find('=');
            if index != -1:
                exploded = token.split('=')
                self.tokenMap[exploded[0]] = exploded[1]

    def getDestinationPort(self):
        try:
            return int(self.tokenMap['DPT'])
        except KeyError:
            return -1

    def getEncryptedData(self, addrIsIPv6):
        try:
            if addrIsIPv6:
                return pack('!HIIH', int(self.tokenMap['FLOWLBL']), int(self.tokenMap['SEQ']), int(self.tokenMap['ACK']), int(self.tokenMap['WINDOW']))
            else:
                return pack('!HIIH', int(self.tokenMap['ID']), int(self.tokenMap['SEQ']), int(self.tokenMap['ACK']), int(self.tokenMap['WINDOW']))
        except KeyError:
            #tokenizer didn't find one of the expected tokens, so this log entry won't have the needed information; indicate that we can stop decryption
            return -1

    def getSourceIP(self):
        return self.tokenMap['SRC']
