#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""SFTP test client based on python-paramiko."""

import logging
import getpass
import optparse
import sys
import re

from os.path import exists, expanduser

import paramiko
import configobj

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
    log_path    - Path of log file for paramiko messages

    """
    # setup logging
    if 'log_path' in config:
        paramiko.util.log_to_file(config['log_path'])

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

def main(args=None):
    optparser = optparse.OptionParser()
    optparser.add_option('-d', '--debug',
        dest="debug", action="store_true",
        help="Enable debug logging")
    optparser.add_option('-c', '--config', dest="configpath",
        default=expanduser('~/.config/sftp_uploader.ini'), metavar="PATH",
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

    sftp, transport = create_sftp_client(config)
    print "\n".join(
        sorted(e for e in sftp.listdir(config.get('remote_dir', '.'))
        if not e.startswith('.')))
    sftp.close()
    transport.close()

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]) or 0)
