"""
Journald log reader event loop for knockknock-daemon.

Contains the JournalReader class which takes no parameters and has 1 method:
(tail)
"""
# Copyright (c) 2015 Jason Ritzke
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

import select
import time
from systemd import journal


class JournalReader:
    """
    Journald reader for knockknock-daemon.

    Takes no parameters on initialization. Has a single event loop method
    called tail that yields new messages in the kernel log.
    """

    def __init__(self):
        """Initalization method for JournalReader class."""
        self.j = journal.Reader()
        self.j.seek_tail()
        self.j.add_match('_TRANSPORT=kernel')
        self.p = select.poll()
        self.p.register(self.j, self.j.get_events())

    def tail(self):
        """Generator that yields messages from the kernel log."""
        while True:
            self.p.poll()
            line = self.j.get_next()
            if 'MESSAGE' not in line:
                time.sleep(.25)
            else:
                yield line['MESSAGE']
