#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""Convenience wrapper for ssh.SFTPClient configured through a config file.

Uses ssh for python (paramiko fork from http://pypi.python.org/pypi/ssh) or
original paramiko.

If called from the comamnd line, tries to log into remote host and
retrieves/prints a listing of the configured remote directory.

"""

__all__ = ['ConfigSFTPClient']

import logging
import getpass
import sys
import re

from os.path import exists, expanduser

try:
    # try paramiko fork first
    import ssh
except:
    # fall back to original paramiko
    import paramiko as ssh

log = logging.getLogger(__name__)


class ConfigSFTPClient(object):
    def __init__(self, config):
        """Create a ssh.SFTPClient instance using the passed config.

        The following config keys are used. Defaults are given in parentheses:

        remote_host - hostname or IP of SFTP server to connect to (localhost)
        remote_port - port number of SFTP server (22)
        username    - user name of account on SFTP server (local user name)
        password    - password for remote account (None, i.e. use key auth)
        private_key - path to private RSA or DSA key file (~/.ssh/id_rsa or
                      ~/.ssh/id_dsa)
        passphrase  - passphrase to use when loading the private key (None)
        ssh_log_path - Path of log file for ssh messages (None)

        """
        self.config = config

        # setup logging
        if config.get('ssh_log_path'):
            ssh.util.log_to_file(config['ssh_log_path'])

        hostname = config.get('remote_host', 'localhost')
        port = config.get('remote_port', 22)
        username = config.get('username', getpass.getuser())
        password = config.get('password')
        private_key = config.get('private_key')
        hostkey = self._load_host_key(hostname)

        log.debug("Connecting to %s, port %s...", hostname, port)
        #~client = ssh.SSHClient()
        #~client.load_system_host_keys()
        #~client.connect(hostname, port, username, password, key_filename=private_key)
        self._transport = tpt = ssh.Transport((hostname, port))
        self._authenticate(tpt, username, password, hostkey, private_key)

        if tpt.is_authenticated():
            log.debug("SSH transport authenticated. Creating SFTP client.")
            # create SFTP client from SSHClient
            self._client = ssh.SFTPClient.from_transport(tpt)
        else:
            raise tpt.get_exception()

    def close(self):
        self._client.close()
        self._transport.close()

    def __getattr__(self, name):
        return getattr(self._client, name)

    def _load_host_key(self, hostname):
        # get host key, if we know one
        keytype = None
        hostkey = None

        try:
            known_hosts = expanduser('~/.ssh/known_hosts')
            host_keys = ssh.util.load_host_keys(known_hosts)
        except (IOError, OSError) as exc:
            log.warning("Could not read known hosts file '%s': %s",
                known_hosts, exc)
        else:
            if hostname in host_keys:
                keytype = host_keys[hostname].keys()[0]
                hostkey = host_keys[hostname][keytype]
                log.info('Using host key: %s/%s', keytype,
                    hostkey.get_fingerprint().encode('hex'))
            else:
                log.warning("No host key found for '%s'. "
                    "Disabling host key check.", hostname)

        return hostkey

    def _load_private_key(self, filename, keytype=None):
        """Load private SSH key from file, return ssh.PKey subclass instance.

        If ``keytype`` is not given, tries to determine the key type
        (RSA or DSA) by loading the key file and looking at the BEGIN RSA/DSA
        PRIVATE KEY line.

        If the key is protected with a passphrase, and no passphrase is
        specified in the config object, prompts user for the passphrase through
        the console.

        """
        type_map = {
            'dsa': ssh.DSSKey,
            'rsa': ssh.RSAKey}

        if keytype is None:
            with open(filename, 'rb') as k:
                keydata = k.read()
            m = re.search("BEGIN (.*?) PRIVATE KEY", keydata)
            if m:
                keytype = m.group(1)

        keycls = type_map.get(keytype.lower(), 'dsa')

        try:
            key = keycls.from_private_key_file(filename)
            log.debug("Loaded key '%s' without password.", filename)
        except ssh.PasswordRequiredException:
            passphrase = self.config.get('passphrase',
                getpass.getpass("Key passphrase: "))
            key = keycls.from_private_key_file(filename, passphrase)

        return key

    def _authenticate(self, transport, username, password=None, hostkey=None,
            pkey=None):
        keys = []

        if not password:
            if not pkey:
                # first try to get key from ssh-agent
                try:
                    log.debug("Fetching keys from SSH agent...")
                    agent = ssh.Agent()
                    keys = list(agent.get_keys())
                    if not keys:
                        raise ValueError
                except (ValueError, ssh.SSHException):
                    log.debug("No keys stored with SSH agent. Trying to load "
                        "keys from ~/.ssh")
                    # failing that, try to find a key on disk
                    for keytype in ('dsa', 'rsa'):
                        pk = expanduser('~/.ssh/id_%s' % keytype)
                        if exists(pk):
                            log.debug("Found %s key: %s", keytype, pk)
                            keys.append(self._load_private_key(pk, keytype))
                            break
            else:
                keys.append(self._load_private_key(pkey))

        saved_exception = None
        for key in keys:
            try:
                transport.connect(username=username, hostkey=hostkey, pkey=key)
                log.debug("Authentication (pubkey) successful. Key: '%s'.",
                    key.get_name())
                return
            except ssh.SSHException as exc:
                log.exception("Exception authenticating using key '%s'",
                    key.get_name())
                saved_exception = exc

        try:
            transport.connect(username=username, password=password,
                hostkey=hostkey)
            log.debug("Authentication (password) successful.")
            if transport.is_authenticated():
                return
        except ssh.SSHException as exc:
            import traceback
            traceback.print_exc(20)
            raise
            saved_exception = exc

        if saved_exception:
            raise saved_exception

def _test(args=None):
    import optparse
    import configobj

    optparser = optparse.OptionParser()
    optparser.add_option('-d', '--debug',
        dest="debug", action="store_true",
        help="Enable debug logging")
    optparser.add_option('-c', '--config', dest="configpath",
        default=expanduser('~/.config/test_sftpclient.ini'), metavar="PATH",
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

    sftp = ConfigSFTPClient(config)
    print "\n".join(
        sorted(e for e in sftp.listdir(config.get('remote_dir', '.'))
        if not e.startswith('.')))
    sftp.close()

if __name__ == '__main__':
    sys.exit(_test(sys.argv[1:]) or 0)
