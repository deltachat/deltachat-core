from __future__ import print_function
import threading
import requests
from . import capi
from .capi import ffi
import deltachat


class EventPrinter:
    def __init__(self, dc_context):
        self.dc_context = dc_context
        self.info = str(self.dc_context).strip(">").split()[-1]

    def __call__(self, evt):
        evt_name, data1, data2 = evt
        t = threading.currentThread()
        tname = getattr(t, "name", t)
        print("[%s-%s]" % (tname, self.info), evt_name, data1, data2)


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
        if not isinstance(content, bytes):
            content = content.encode("utf8")
        # we need to return a fresh pointer that the core owns
        return capi.lib.dupstring_helper(content)

    def dc_event_is_offline(self, data1, data2):
        return 0  # always online


class Contact:
    def __init__(self, dc_context, contact_id):
        self.dc_context = dc_context
        self.id = contact_id
        # XXX do we need to free dc_contact_t? (we own it according to API)
        self.dc_contact_t = capi.lib.dc_get_contact(self.dc_context, contact_id)

    @property
    def addr(self):
        return ffi_unicode(capi.lib.dc_contact_get_addr(self.dc_contact_t))

    @property
    def display_name(self):
        return ffi_unicode(capi.lib.dc_contact_get_display_name(self.dc_contact_t))

    @property
    def is_blocked(self):
        return capi.lib.dc_contact_is_blocked(self.dc_contact_t)

    @property
    def is_verified(self):
        return capi.lib.dc_contact_is_verified(self.dc_contact_t)


class Chat:
    def __init__(self, dc_context, chat_id):
        self.dc_context = dc_context
        self.id = chat_id

    def send_text_message(self, msg):
        msg = convert_bytes(msg)
        return capi.lib.dc_send_text_msg(self.dc_context, self.id, msg)


class Account:
    def __init__(self, db_path, logcallback=None, eventhandler=None):
        self.dc_context = ctx = capi.lib.dc_context_new(
                                  capi.lib.py_dc_callback,
                                  capi.ffi.NULL, capi.ffi.NULL)
        if hasattr(db_path, "encode"):
            db_path = db_path.encode("utf8")
        capi.lib.dc_open(ctx, db_path, capi.ffi.NULL)
        if logcallback is None:
            logcallback = EventPrinter(self.dc_context)
        self._logcallback = logcallback
        if eventhandler is None:
            eventhandler = EventHandler(self.dc_context)
        self._eventhandler = eventhandler
        self._threads = IOThreads(self.dc_context)

    def set_config(self, **kwargs):
        for name, value in kwargs.items():
            name = name.encode("utf8")
            value = value.encode("utf8")
            capi.lib.dc_set_config(self.dc_context, name, value)

    def get_config(self, name):
        name = name.encode("utf8")
        res = capi.lib.dc_get_config(self.dc_context, name, b'')
        return ffi_unicode(res)

    def get_self_contact(self):
        return Contact(self.dc_context, capi.lib.DC_CONTACT_ID_SELF)

    def create_contact(self, emailadr, name=ffi.NULL):
        name = convert_bytes(name)
        emailadr = convert_bytes(emailadr)
        contact_id = capi.lib.dc_create_contact(self.dc_context, name, emailadr)
        return Contact(self.dc_context, contact_id)

    def create_chat_by_contact(self, contact):
        chat_id = capi.lib.dc_create_chat_by_contact_id(self.dc_context, contact.id)
        return Chat(self.dc_context, chat_id)

    def start(self):
        deltachat.set_context_callback(self.dc_context, self._process_event)
        capi.lib.dc_configure(self.dc_context)
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

    def _process_event(self, ctx, evt_name, data1, data2):
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


def convert_bytes(obj):
    if obj == ffi.NULL:
        return obj
    if not isinstance(obj, bytes):
        return obj.encode("utf8")
    return obj


def ffi_unicode(obj):
    return ffi.string(obj).decode("utf8")
