"""Example script for using sftpclient.ConfigSFTPClient under Pythonista."""

from __future__ import print_function

import stat
import sys

from os.path import dirname, expanduser, join

import console
import keychain

import sftpclient

stored_password = False

ssh_dir = join(expanduser('~'), 'Documents', '.ssh')
config = dict(
    remote_host='chrisarndt.de',
    username='chris',
    ssh_log_path=join(ssh_dir, 'sftpclientlog.txt'),
    ssh_dir=ssh_dir
)

service = 'ssh://%s' % config['remote_host']

if not config.get('password'):
    stored_password = keychain.get_password(service, config['username'])
    if stored_password:
        config['password'] = stored_password

if not config.get('password'):
    try:
        config['password'] = console.password_alert('Enter password',
            "Please enter password for '%s' on '%s':" %
            (config['username'], config['remote_host']))
    except KeyboardInterrupt:
        pass

sftp = sftpclient.ConfigSFTPClient(config)

if config.get('password') and (not stored_password or stored_password != config.get('password')):
    try:
        choice = console.alert('Store password?',
            "Save password for service '%s' and account '%s'?" %
            (service, config['username']), 'Yes')
    except KeyboardInterrupt:
        pass
    else:
        if choice == 1:
            keychain.set_password(service, config['username'], config['password'])

dirent = [f for f in sftp.listdir_attr('.') if not f.filename.startswith('.')]
print(" ".join(sorted(f.filename for f in dirent if stat.S_IFMT(f.st_mode) == stat.S_IFDIR)))
print(" ".join(sorted(f.filename for f in dirent if stat.S_IFMT(f.st_mode) != stat.S_IFDIR)))
sftp.close()
