#!/usr/bin/env python3

from sys import argv
from os import path, remove, popen
from shutil import copyfile, rmtree
from distutils.core import setup, Extension

if argv[1] != 'sdist':
    copyfile('knockknock-daemon.py', 'knockknock/knockknock-daemon')
    copyfile('knockknock-genprofile.py', 'knockknock/knockknock-genprofile')
    copyfile('knockknock-proxy.py', 'knockknock/knockknock-proxy')
    copyfile('knockknock.py', 'knockknock/knockknock')

setup  (name         = 'knockknock',
        version      = '0.8',
        description  = 'A cryptographic single-packet port-knocker.',
        author       = 'Moxie Marlinspike',
        author_email = 'moxie@thoughtcrime.org',
        url          = 'http://www.thoughtcrime.org/software/knockknock/',
        license      = 'GPL',
        packages     = ['knockknock', 'knockknock.proxy'],
        scripts      = ['knockknock/knockknock-daemon',
                        'knockknock/knockknock-genprofile',
                        'knockknock/knockknock-proxy',
                        'knockknock/knockknock'],
        data_files   = [('', ['minimal-firewall.sh', 'knockknock-daemon.py', 
                              'knockknock-genprofile.py', 'knockknock-proxy.py', 
                              'knockknock.py']),
                        ('share/knockknock', ['README', 'INSTALL', 'COPYING']),
                        ('/etc/knockknock.d/', ['config'])]
       )

print('Cleaning up...')

if path.exists('build/'):
    rmtree('build/')

try:
    remove('knockknock/knockknock-proxy')
    remove('knockknock/knockknock-daemon')
    remove('knockknock/knockknock-genprofile')
    remove('knockknock/knockknock')

except:
    pass

def capture(cmd):
    return popen(cmd).read().strip()
