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

import os, hmac, hashlib, sys
from .MacFailedException import MacFailedException
from Crypto.Cipher import AES
from struct import *

class CryptoEngine:

    def __init__(self, profile, cipherKey, macKey, counter):
        self.profile   = profile
        self.counter   = counter
        self.macKey    = macKey
        self.cipherKey = cipherKey
        self.cipher    = AES.new(self.cipherKey, AES.MODE_ECB)

    def calculateMac(self, port):
        hmacSha = hmac.new(self.macKey, port, hashlib.sha1)
        mac     = hmacSha.digest()
        return mac[:10]

    def verifyMac(self, port, remoteMac):
        localMac = self.calculateMac(port)

        if (not localMac == remoteMac):
            raise MacFailedException('MAC doesn''t match!')

    def encryptCounter(self, counter):
        counterBytes = pack('!IIII', 0, 0, 0, counter)
        return self.cipher.encrypt(counterBytes)

    def encrypt(self, plaintextData):
        plaintextData += self.calculateMac(plaintextData)
        counterCrypt   = self.encryptCounter(self.counter)
        self.counter   = self.counter + 1

        encrypted = bytearray()
        for i in range(len(plaintextData)):
            encrypted.append(plaintextData[i] ^ counterCrypt[i])

        self.profile.setCounter(self.counter)
        self.profile.storeCounter()
        return encrypted

    def decrypt(self, encryptedData, windowSize):
        for x in range(windowSize):
            try:
                counterCrypt = self.encryptCounter(self.counter + x)
                decrypted = bytearray()
                for i in range((len(encryptedData))):
                    decrypted.append(encryptedData[i] ^ counterCrypt[i])

                port = decrypted[:2]
                mac  = decrypted[2:]
                self.verifyMac(port, mac)
                self.counter += x + 1

                self.profile.setCounter(self.counter)
                self.profile.storeCounter()

                return int(unpack('!H', port)[0])

            except MacFailedException:
                pass

        raise MacFailedException('Ciphertext failed to decrypt in range...')
