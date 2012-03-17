# -*- coding: utf-8 -*-
# Copyright (C) 2009 www.stani.be
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/
#
# Follows PEP8
#
# Original from: http://bazaar.launchpad.net/~stani/phatch/trunk/view/head:/phatch/lib/notify.py
#

APP_NAME = 'notify.py'

# pynotify (linux)
try:
    import pynotifyx
    import gobject
    gobject.threads_init()
except ImportError:
    pynotify = None

# Growl (Mac Os X)
if pynotify:
    Growl = None
else:
    try:
        import Growl
    except ImportError:
        Growl = None

# Toasterbox (Windows)
if pynotify or Growl:
    TB = None
else:
    try:
        import wx
        import wx.lib.agw.toasterbox as TB
    except ImportError:
        TB = None


def register(app_name):
    global APP_NAME
    APP_NAME = app_name

def init(app_name, icon=None):
    register(app_name)

if pynotify:
    def init(app_name, icon=None):
        register(app_name)
        pynotify.init(app_name)

    def notify(title, message, icon='gtk-dialog-info', wxicon=None,
            urgency=None, timeout=None):
        n = pynotify.Notification(title, message, icon)
        if urgency:
            n.set_urgency(getattr(pynotify,
                'URGENCY_%s' % urgency.upper()))
        if timeout:
            n.set_timeout(timeout)
        n.show()

elif Growl:
    def init(app_name, icon=None):
        """Create a growl notifier with appropriate icon if specified.

        The notification classes default to [APP_NAME]. The user can
        enable/disable notifications based on this class name.

        """
        global growl
        register(app_name)
        if icon is None:
            icon = {}
        else:
            icon = {'applicationIcon': Growl.Image.imageFromPath(icon)}
        growl = Growl.GrowlNotifier(APP_NAME, [APP_NAME], **icon)

    def notify(title, message, icon='gtk-dialog-info', wxicon=None,
            urgency=None, timeout=None):
        growl.notify(APP_NAME, title, message)

elif TB:
    import atexit

    from threading import Thread, Event
    from Queue import Queue, Empty

    # global Notifier instance, created on demand
    NOTIFIER = None

    class Notifier(Thread):
        def __init__(self, app_name, icon=None):
            Thread.__init__(self)
            self.app_name = app_name
            self.icon = icon
            self.queue = Queue()
            self.app = wx.PySimpleApp()
            # dummy frame as top-level window
            self.frame = wx.Frame(None)
            self.timer = wx.Timer()
            self.daemon = True
            self.start()

        def run(self, *args):
            self.app.Bind(wx.EVT_TIMER, self._check_queue, self.timer)
            self.timer.Start(50)
            self.app.MainLoop()

        def stop(self):
            self.queue.put(None)

        def _check_queue(self, event):
            try:
                event = self.queue.get_nowait()
            except Empty:
                pass
            else:
                if event is None:
                    self.timer.Stop()
                    self.frame.Destroy()
                else:
                    args, kwargs = event
                    self._notify(*args, **kwargs)

        def notify(self, *args, **kwargs):
            self.queue.put((args, kwargs))

        def _notify(self, title, message, icon='gtk-dialog-info',
                wxicon=None, urgency=None, timeout=5):
            if wxicon is None:
                wxicon = wx.ArtProvider_GetBitmap(wx.ART_INFORMATION,
                    wx.ART_OTHER, (48, 48))

            tb = TB.ToasterBox(self.app.GetTopWindow(),
                TB.TB_COMPLEX, TB.TB_DEFAULT_STYLE, TB.TB_ONCLICK)
            tb.SetPopupSize((300, 80))
            tb.SetPopupPauseTime(timeout * 1000)
            tb.SetPopupScrollSpeed(10)
            tb.SetPopupPositionByInt(3)

            # wx controls
            tbpanel = tb.GetToasterBoxWindow()
            panel = wx.Panel(tbpanel, -1)
            panel.SetBackgroundColour(wx.WHITE)
            wxicon = wx.StaticBitmap(panel, -1, wxicon)
            title = wx.StaticText(panel, -1, title)
            message = wx.StaticText(panel, -1, message)

            # wx layout controls
            ver_sizer = wx.BoxSizer(wx.VERTICAL)
            ver_sizer.Add(title, 0, wx.ALL, 4)
            ver_sizer.Add(message, 0, wx.ALL, 4)

            hor_sizer = wx.BoxSizer(wx.HORIZONTAL)
            hor_sizer.Add(wxicon, 0, wx.EXPAND | wx.ALIGN_CENTER_VERTICAL \
                | wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 4)
            hor_sizer.Add(ver_sizer, 1, wx.EXPAND)
            hor_sizer.Layout()
            panel.SetSizer(hor_sizer)

            tb.AddPanel(panel)
            tb.show()
            tb.Play()

    def init(app_name, icon=None):
        global NOTIFIER
        register(app_name)
        if NOTIFIER is None:
            NOTIFIER = Notifier(app_name, icon)
            atexit.register(quit)

    def notify(title, message, icon= 'gtk-dialog-info', wxicon=None,
            urgency=None, timeout=5):
        if NOTIFIER is None:
            init(APP_NAME)
        NOTIFIER.notify(title, message, icon, wxicon, urgency, timeout)

    def quit():
        if NOTIFIER:
            NOTIFIER.stop()
            NOTIFIER.join()
            NOTIFIER = None
else:
    def notify(*args, **kw):
        pass


if __name__ == '__main__':
    import time
    init(APP_NAME)
    notify("Urgent Message:", "Don't pee on an electrical fence!",
        urgency='critical', timeout=5)
    notify("Public announcement:", "SPAMM! SPAMM! SPAMM!", urgency='low',
        timeout=3)
    notify("Information:", "My hovercraft is full of eels.", timeout=5)
    time.sleep(6)
