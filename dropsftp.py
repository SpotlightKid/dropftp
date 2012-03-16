#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""Watch a folder and upload new/changed files to a remote host via SFTP.

Also displays notifications via Growl.

Dependencies
------------

* MacFSEvents: https://github.com/malthe/macfsevents
* ConfigObj: http://www.voidspace.org.uk/python/configobj.html
* Ssh for Python: http://pypi.python.org/pypi/ssh (or original paramiko)
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
import Growl

from fsevents import Stream, Observer, IN_CREATE, IN_MODIFY

from sftpclient import ConfigSFTPClient

__author__ = "Christopher Arndt"
__version__ = "1.0.1"
__revision__ = "$Rev$"
__license__ = "MIT License"
__usage__ = "%prog [-d|--debug] [-c|--config <config.ini>]"

log = logging.getLogger("dropsftp")


class FSEventUploader(object):
    """Watch a directory via FSEvents and upload new/changed files via SFTP
    to a remote host.

    """
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
                sftp = ConfigSFTPClient(self.config)
                sftp.put(event.name, remote_path)
            except:
                self.growl.notify('error', "File upload", "Upload error")
            else:
                self.growl.notify('info', "File upload", "Upload successful")
                sftp.close()

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
