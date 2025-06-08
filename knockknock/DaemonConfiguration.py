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

from configparser import ConfigParser, NoSectionError
#from .knockknock_logging import do_log     # debug

class DaemonConfiguration:

    def __init__(self, file):
        try:
            parser = ConfigParser({'delay': '15', 'error_window': '20'})
            parser.read(file)

            self.delay  = parser.getint('main', 'delay')
            self.window = parser.getint('main', 'error_window')
            self.logging = parser.get(section='main', option='logging', fallback=None)
            # TODO: should there be a default log location?
            self.logfile = parser.get(section='main', option='logfile', fallback='/var/log/kern.log')
            #do_log(f'config file - defaults: delay: {self.delay}, window: {self.window}, '
            #       f'logging: {self.logging}, logfile: {self.logfile}')
        except NoSectionError:
            print('knockknock-daemon: config file not found, assuming defaults.')
            self.delay  = 15
            self.window = 20
            self.logging = None     # None means "no preference"
            self.logfile = '/var/log/kern.log'
            #do_log(f'config file not found, assuming defaults: delay: {self.delay}, window: {self.window}, '
            #       f'logging: {self.logging}, logfile: {self.logfile}')

    def getDelay(self):
        return self.delay

    def getWindow(self):
        return self.window

    def getLogging(self):
        return self.logging
