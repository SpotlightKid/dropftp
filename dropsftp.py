#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""Watch a folder and upload new/changed files to a remote host via SFTP.

Also displays notifications via Growl.

Dependencies
------------

* MacFSEvents: https://github.com/malthe/macfsevents
* ConfigObj: http://www.voidspace.org.uk/python/configobj.html
* Paramiko: http://www.lag.net/paramiko/
* Growl 1.2.2: http://growl.info/downloads

"""

import logging
import getpass
import optparse
import os
import sys
import time
import re

from os.path import basename, exists, expanduser, isfile, isdir, join

import configobj
import paramiko
import Growl

from fsevents import Stream, Observer, IN_CREATE, IN_MODIFY

__author__ = "Christopher Arndt"
__version__ = "1.0.1"
__revision__ = "$Rev$"
__license__ = "MIT License"
__usage__ = "%prog [-d|--debug] [-c|--config <config.ini>]"

log = logging.getLogger("dropsftp")

def _load_key(filename, config, type_=None):
    type_map = {
        'dsa': paramiko.DSSKey,
        'rsa': paramiko.RSAKey}

    if type_ is None:
        keydata = open(filename, 'rb').read()
        m = re.search("BEGIN (.*?) PRIVATE KEY")
        if m:
            type_ = m.group(1)

    keycls = type_map.get(type_.lower(), 'dsa')

    try:
        key = keycls.from_private_key_file(filename)
        log.debug("Loaded key '%s' without password.", filename)
    except paramiko.PasswordRequiredException:
        passphrase = config.get('passphrase',
            getpass.getpass("Key passphrase: "))
        key = keycls.from_private_key_file(filename, passphrase)
    return key

def create_sftp_client(config):
    """Create a paramiko.SFTPClient instance using the passed config.

    The following config keys are used. Defaults are given in parentheses:

    remote_host - hostname or IP of SFTP server to connect to (localhost)
    remote_port - port number of SFTP server (22)
    username    - user name of account on SFTP server (local user name)
    password    - password for remote account (None, i.e. use key auth)
    private_key - path to private RSA or DSA key file (~/.ssh/id_rsa or
                  ~/.ssh/id_dsa)
    passphrase  - passphrase to use when loading the private key (None)
    ssh_log_path - Path of log file for paramiko messages

    """
    # setup logging
    if config.get('ssh_log_path'):
        paramiko.util.log_to_file(config['ssh_log_path'])

    hostname = config.get('remote_host', 'localhost')
    port = config.get('remote_port', 22)
    username = config.get('username', getpass.getuser())
    password = config.get('password')
    private_key = config.get('private_key')
    keys = []

    if not password:
        if not private_key:
            # first try to get key from ssh-agent
            try:
                log.debug("Fetching keys from SSH agent...")
                agent = paramiko.Agent()
                keys = list(agent.get_keys())
                agent.close()
                if not keys:
                    raise ValueError
            except (ValueError, paramiko.SSHException):
                log.debug("No keys stored with SSH agent. Trying to load keys"
                    "from ~/.ssh")
                # failing that, try to find a key on disk
                for type_ in ('dsa', 'rsa'):
                    pk = expanduser('~/.ssh/id_%s' % type_)
                    if exists(pk):
                        log.debug("Found %s key: %s", type_, pk)
                        keys.append(_load_key(pk, config, type_))
                        break
        else:
            # XXX: assume DSA-Key
            keys.append(_load_key(private_key, config))

    # get host key, if we know one
    hostkeytype = None
    hostkey = None
    try:
        known_hosts = expanduser('~/.ssh/known_hosts')
        host_keys = paramiko.util.load_host_keys(known_hosts)
    except (IOError, OSError) as exc:
        log.warning("Could not read known hosts file '%s': %s", known_hosts,
            exc)
        hostkey = None
    else:
        if hostname in host_keys:
            keytype = host_keys[hostname].keys()[0]
            hostkey = host_keys[hostname][keytype]
            log.info('Using host key: %s/%s', keytype,
                " ".join("%02X" % ord(c) for c in hostkey.get_fingerprint()))
        else:
            log.warning("No host key found for '%s'. Disabling host key check.",
                hostname)

    # now, connect and use paramiko Transport to negotiate SSH2 across the
    # connection
    log.debug("Connection to %s, port %s...", hostname, port)
    tpt = paramiko.Transport((hostname, port))
    if keys:
        for key in keys:
            try:
                tpt.connect(username=username, password=password, hostkey=hostkey,
                    pkey=key)
                break
            except paramiko.SSHException:
                pass
    else:
        tpt.connect(username=username, password=password, hostkey=hostkey)

    if tpt.is_authenticated():
        # create SFTP client from transport
        return paramiko.SFTPClient.from_transport(tpt), tpt
    else:
        raise tpt.get_exception()


class FSEventUploader(object):
    name = 'dropsftp'
    
    def __init__(self, config):
        self.growl = Growl.GrowlNotifier(
            applicationName=self.name, notifications=['info', 'error'])
        self.growl.register()
        self.config = config
        self.directory = config.get('local_dir', os.getcwd())
        self.stream = Stream(self._callback, self.directory, file_events=True)
        self.observer = Observer()
        self.observer.schedule(self.stream)
        self.observer.start()

    def _callback(self, event):
        log.debug("FileEvent received: %r", event)
        if event.mask & (IN_CREATE | IN_MODIFY) and isfile(event.name):
            # disregard hidden files
            if basename(event.name).startswith('.'):
                return

            # show notification
            self.growl.notify('info',
                "File created", "New file: %s" % event.name)

            # upload file
            remote_path = join(self.config.get('remote_dir', ''),
                basename(event.name))

            self.growl.notify('info',
                "File upload", "Uploading file to:\n%s:%s" % (
                    self.config['remote_host'], remote_path))

            try:
                sftp, transport = create_sftp_client(self.config)
                sftp.put(event.name, remote_path)
            except:
                self.growl.notify('error', "File upload", "Upload error")
            else:
                self.growl.notify('info', "File upload", "Upload successful")
                sftp.close()
                transport.close()
        
    def close(self):
        self.observer.stop()
        self.observer.join()
        self.stream.close()


def main(args=None):
    optparser = optparse.OptionParser(usage=__usage__,
        description=__doc__.splitlines()[0], version=__version__)
    optparser.add_option('-d', '--debug',
        dest="debug", action="store_true",
        help="Enable debug logging")
    optparser.add_option('-c', '--config', dest="configpath",
        default=expanduser('~/.config/dropsftp.ini'), metavar="PATH",
        help="Path to configuration file (default: %default)")

    if args is None:
        options, args = optparser.parse_args(args)
    else:
        options, args = optparser.parse_args(sys.argv[1:])

    config = configobj.ConfigObj(options.configpath)

    if options.debug:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    if 'log_path' in config:
        logging.basicConfig(filename=config['log_path'], level=loglevel)
    else:
        logging.basicConfig(level=loglevel)

    growler = FSEventUploader(config)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        growler.close()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
