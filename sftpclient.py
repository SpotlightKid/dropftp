#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""Convenience wrapper for ``ssh.SFTPClient`` configured via a config file/dict.

Uses ssh for python (paramiko fork from http://pypi.python.org/pypi/ssh) or
original paramiko.

If called from the command line, tries to log into remote host and retrieves &
prints a listing of the remote directory. The remote directory can be given as
the first non-option argument on the comamnd line or specified in the config
file under the key ``'remote_dir'``. If neither is given, the current
directory, i.e. the user's working directory after log in, is used.

"""

__all__ = ['ConfigSFTPClient']

import itertools
import logging
import getpass
import sys
import re

from os.path import abspath, dirname, exists, expanduser, join

try:
    # try paramiko fork first
    import ssh
except:
    # fall back to original paramiko
    import paramiko as ssh

log = logging.getLogger(__name__)


class ConfigSFTPClient(object):
    """A wrapper for ssh.SFTPClient configured via a config dict."""

    def __init__(self, config):
        """Create a ssh.SFTPClient instance using the passed config dictionary.

        The following config keys are used. Defaults are given in parentheses:

        ``remote_host`` - hostname or IP address of SFTP server to connect to
                          (``'localhost'``)
        ``remote_port`` - port number of SFTP server (``22``)
        ``username``    - user name of account on SFTP server (local user name)
        ``password``    - password for remote account (``None``, i.e. try key
                          authentication)
        ``private_key`` - path to private RSA or DSA key file or ``ssh.PKey``
                          sub-class instance (``None``)
        ``passphrase``  - passphrase to use when loading the private key
                          or callable, which takes three arguments (key
                          filename, hostname and username) and returns a 
                          passphrase or ``None`` (``None``)
        ``compress``    - When ``True``, enable transport data compression
                          (``False``)
        ``ssh_log_path`` - Path of log file for SSH messages (``None``)
        ``ssh_dir``     - directory in which to look for ``known_hosts`` file
                          and private key files (``'~/.ssh'``)
        
        If no or an empty ``password`` is given, the given ``private_key`` will
        be used for authentication. ``private_key`` can be a path to a key 
        file, which will be loaded using the provided ``passphrase``, if 
        necessary, or an instance of a sub-class of ``ssh.PKey``, which will be 
        used as-is.

        If no ``private_key`` is provided either, the keys available through a
        SSH agent, if any, and any keys found in the user's SSH dir will be
        tried in that order. To discover a running SSH agent, the
        ``SSH_AUTH_SOCK`` environment variable must point to a socket file,
        through which a  connection to the agent can be established. Private 
        key files in the user's SSH dir must be in OpenSSH RSA or DSA format
        and be named ``'id_rsa'`` or ``'id_dsa'`` resp.

        If a passphrase is required to load a key file, the value of
        ``passphrase`` set in the config dict will be used directly, if it is
        a string. If ``passphrase`` is a callable, it will be called with the
        filename, hostname and username as arguments and is expected to return
        the passphrase string or ``None``, if the key should be skipped. If no
        passphrase is given in the config, the user is prompted for the 
        passphrase through the console, as a last resort.

        For remote host verification, a host key will be searched and loaded
        from the ``known_hosts`` file in the user's SSH dir, i.e. the path set
        with the config key ``'ssh_dir'`` or ``'~/.ssh'``. If no host key is
        found, no host verification is done.

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
        self._transport = tpt = ssh.Transport((hostname, port))
        tpt.use_compression(compress=config.get('compress', False))
        self._authenticate(tpt, username, password, hostkey, private_key)

        if tpt.is_authenticated():
            log.debug("SSH transport authenticated. Creating SFTP client.")
            # create SFTP client from SSHClient
            self._client = ssh.SFTPClient.from_transport(tpt)
        else:
            raise tpt.get_exception()

    def close(self):
        """Close the ``ssh.SFTPClient`` instance and the SSH transport."""
        self._client.close()
        self._transport.close()

    def __getattr__(self, name):
        """Delegate attribute lookup to ``ssh.SFTPClient`` instance."""
        return getattr(self._client, name)

    def _load_host_key(self, hostname):
        """Load host key for given hostname from known hosts file.
        
        Looks for the known hosts file under the filename 'known_hosts' in the
        user's SSH dir, i.e. the path set with the config key ``'ssh_dir'`` or
        ``'~/.ssh'``.
        
        Returns a ``ssh.HostKey`` instance or ``None``, if no key for the host
        was found.

        """
        # get host key, if we know one
        hostkey = None

        try:
            known_hosts = join(self.config.get('ssh_dir',
                expanduser('~/.ssh')), 'known_hosts')
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
        """Load private SSH key from file, return ``ssh.PKey`` sub-class instance.

        If ``keytype`` is not given, tries to determine the key type
        (RSA or DSA) by loading the key file and looking at the BEGIN RSA/DSA
        PRIVATE KEY line.

        See the documentation of the constructor on the details of key
        passphrase handling.

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
            passphrase = self.config.get('passphrase')
            
            if callable(passphrase):
                passphrase = passphrase(filename,
                    self.config.get('remote_host', 'localhost'),
                    self.config.get('username', getpass.getuser()))
                if passphrase is None:
                    return

            if not passphrase:
                passphrase = getpass.getpass("Key passphrase: ")
            
            key = keycls.from_private_key_file(filename, passphrase)

        return key

    def _authenticate(self, transport, username, password=None, hostkey=None,
            pkey=None):
        """Perform authentication of SSH transport using given credentials.
        
        See documentation of the constructor for details on the authentication
        methods.

        """
        if not password:
            if pkey:
                if not isinstance(pkey, (tuple, list)):
                    pkey = [pkey]
            else:
                log.debug("Fetching keys from SSH agent...")
                agent = ssh.Agent()
                agent_keys = agent.get_keys()
                log.debug("Agent keys: %r", agent_keys)
                key_files = [join(self.config.get('ssh_dir',
                    expanduser('~/.ssh')), 'id_%s' % keytype)
                    for keytype in ('dsa', 'rsa')]
                pkey = itertools.chain(agent_keys, key_files)
                
            saved_exception = None
            for key in pkey:
                if not isinstance(key, ssh.PKey):
                    if not exists(key):
                        continue
                    
                    log.debug("Loading key file: %s", key)
                    key = self._load_private_key(key)
                
                try:
                    transport.connect(username=username, hostkey=hostkey,
                        pkey=key)
                    if transport.is_authenticated():
                        log.info("Authentication (pubkey) successful. "
                            "Key: '%s'.", key.get_name())
                        return
                except ssh.SSHException as exc:
                    log.info("Authenticating using key '%s' failed.",
                        key.get_name())
                    saved_exception = exc

        try:
            transport.connect(username=username, password=password,
                hostkey=hostkey)
            log.info("Authentication (password) successful.")
            if transport.is_authenticated():
                return
        except ssh.SSHException as exc:
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
        default=expanduser('~/.config/sftpclient.ini'), metavar="PATH",
        help="Path to configuration file (default: %default)")

    if args is None:
        options, args = optparser.parse_args(args)
    else:
        options, args = optparser.parse_args(sys.argv[1:])

    try:
        config = configobj.ConfigObj(options.configpath, file_error=True)
    except (OSError, IOError) as exc:
        sys.stderr.write("Error opening config file: %s\n" % exc)
        return 1

    if options.debug:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    if 'log_path' in config:
        logging.basicConfig(filename=config['log_path'], level=loglevel)
    else:
        logging.basicConfig(level=loglevel)

    if not config.get('passphrase'):
        import subprocess
        
        if sys.platform == 'darwin':
            ssh_askpass = join(abspath(dirname(__file__)), 'macosx-askpass')
        else:
            ssh_askpass = 'ssh-askpass'

        def get_passphrase(*args):
            try:
                return subprocess.check_output(
                    [ssh_askpass, "Please enter SSH key passphrase:"]).strip()
            except subprocess.CalledProcessError:
                return None

        config['passphrase'] = get_passphrase

    if args:
        remote_dir = args.pop(0)
    else:
        remote_dir = config.get('remote_dir', '.')

    sftp = ConfigSFTPClient(config)
    print "\n".join(
        sorted(e for e in sftp.listdir(remote_dir)
        if not e.startswith('.')))
    sftp.close()


if __name__ == '__main__':
    sys.exit(_test(sys.argv[1:]) or 0)
