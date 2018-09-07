from __future__ import print_function
import threading
import requests
from . import capi
import deltachat


def eventprinter(evt):
    evt_name, data1, data2 = evt
    t = threading.currentThread()
    tname = getattr(t, "name", t)
    print("[" + tname + "]", evt_name, data1, data2)


class EventHandler:
    def __init__(self, dc_context):
        self.dc_context = dc_context

    def read_url(self, url):
        try:
            r = requests.get(url)
        except requests.ConnectionError:
            return ''
        else:
            return r.content

    def dc_event_http_get(self, data1, data2):
        url = data1
        content = self.read_url(url)
        # we need to return a fresh pointer that the core owns
        return capi.lib.dupstring_helper(content)

    def dc_event_is_offline(self, data1, data2):
        return 0  # always online


class Account:
    def __init__(self, db_path, logcallback=None, eventhandler=None):
        self.dc_context = ctx = capi.lib.dc_context_new(
                                  capi.lib.py_dc_callback,
                                  capi.ffi.NULL, capi.ffi.NULL)
        if hasattr(db_path, "encode"):
            db_path = db_path.encode("utf8")
        capi.lib.dc_open(ctx, db_path, capi.ffi.NULL)
        self._logcallback = logcallback or eventprinter
        if eventhandler is None:
            eventhandler = EventHandler(self.dc_context)
        self._eventhandler = eventhandler

    def set_config(self, **kwargs):
        for name, value in kwargs.items():
            name = name.encode("utf8")
            value = value.encode("utf8")
            capi.lib.dc_set_config(self.dc_context, name, value)

    def start(self):
        deltachat.set_context_callback(self.dc_context, self.process_event)
        capi.lib.dc_configure(self.dc_context)
        self._threads = IOThreads(self.dc_context)
        self._threads.start()

    def shutdown(self):
        deltachat.clear_context_callback(self.dc_context)
        self._threads.stop(wait=False)
        # XXX actually we'd like to wait but the smtp/imap
        # interrupt idle calls do not seem to release the
        # blocking call to smtp|imap idle. This means we
        # also can't now close the database because the
        # threads might still need it.
        # capi.lib.dc_close(self.dc_context)

    def process_event(self, ctx, evt_name, data1, data2):
        assert ctx == self.dc_context
        self._logcallback((evt_name, data1, data2))
        method = getattr(self._eventhandler, evt_name.lower(), None)
        if method is not None:
            return method(data1, data2) or 0
        return 0


class IOThreads:
    def __init__(self, dc_context):
        self.dc_context = dc_context
        self._thread_quitflag = False
        self._name2thread = {}

    def start(self, imap=True, smtp=True):
        assert not self._name2thread
        if imap:
            self._start_one_thread("imap", self.imap_thread_run)
        if smtp:
            self._start_one_thread("smtp", self.smtp_thread_run)

    def _start_one_thread(self, name, func):
        self._name2thread[name] = t = threading.Thread(target=func, name=name)
        t.setDaemon(1)
        t.start()

    def stop(self, wait=False):
        self._thread_quitflag = True
        # XXX interrupting does not quite work yet, the threads keep idling
        print("interrupting smtp and idle")
        capi.lib.dc_interrupt_imap_idle(self.dc_context)
        capi.lib.dc_interrupt_smtp_idle(self.dc_context)
        if wait:
            for name, thread in self._name2thread.items():
                thread.join()

    def imap_thread_run(self):
        print ("starting imap thread")
        while not self._thread_quitflag:
            capi.lib.dc_perform_imap_jobs(self.dc_context)
            capi.lib.dc_perform_imap_fetch(self.dc_context)
            capi.lib.dc_perform_imap_idle(self.dc_context)

    def smtp_thread_run(self):
        print ("starting smtp thread")
        while not self._thread_quitflag:
            capi.lib.dc_perform_smtp_jobs(self.dc_context)
            capi.lib.dc_perform_smtp_idle(self.dc_context)
