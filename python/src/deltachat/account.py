from __future__ import print_function
import threading
import re
import requests
try:
    from queue import Queue
except ImportError:
    from Queue import Queue

from . import capi
from .capi import ffi
import deltachat


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


class EventLogger:
    def __init__(self, dc_context, _logid=None, debug=True):
        self.dc_context = dc_context
        self._event_queue = Queue()
        self._debug = debug
        if _logid is None:
            _logid = str(self.dc_context).strip(">").split()[-1]
        self._logid = _logid
        self._timeout = None

    def __call__(self, evt_name, data1, data2):
        self._log_event(evt_name, data1, data2)
        self._event_queue.put((evt_name, data1, data2))

    def set_timeout(self, timeout):
        self._timeout = timeout

    def get(self, timeout=None, check_error=True):
        timeout = timeout or self._timeout
        ev = self._event_queue.get(timeout=timeout)
        if check_error and ev[0] == "DC_EVENT_ERROR":
            raise ValueError("{}({!r},{!r})".format(*ev))
        return ev

    def get_matching(self, event_name_regex):
        rex = re.compile("(?:{}).*".format(event_name_regex))
        while 1:
            ev = self.get()
            if rex.match(ev[0]):
                return ev

    def _log_event(self, evt_name, data1, data2):
        if self._debug:
            t = threading.currentThread()
            tname = getattr(t, "name", t)
            print("[{}-{}] {}({!r},{!r})".format(
                 tname, self._logid, evt_name, data1, data2))


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
        """ return ID of the message in this chat.
        'msg' should be unicode"""
        msg = convert_bytes(msg)
        print ("chat id", self.id)
        return capi.lib.dc_send_text_msg(self.dc_context, self.id, msg)


class Message:
    def __init__(self, dc_context, msg_id):
        self.dc_context = dc_context
        self.id = msg_id
        self.dc_msg = capi.lib.dc_get_msg(self.dc_context, msg_id)

    @property
    def text(self):
        return ffi_unicode(capi.lib.dc_msg_get_text(self.dc_msg))


class Account:
    def __init__(self, db_path, _logid=None):
        self.dc_context = ctx = capi.lib.dc_context_new(
                                  capi.lib.py_dc_callback,
                                  capi.ffi.NULL, capi.ffi.NULL)
        if hasattr(db_path, "encode"):
            db_path = db_path.encode("utf8")
        capi.lib.dc_open(ctx, db_path, capi.ffi.NULL)
        self._evhandler = EventHandler(self.dc_context)
        self._evlogger = EventLogger(self.dc_context, _logid)
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

    def create_contact(self, email, name=ffi.NULL):
        name = convert_bytes(name)
        email = convert_bytes(email)
        contact_id = capi.lib.dc_create_contact(self.dc_context, name, email)
        return Contact(self.dc_context, contact_id)

    def create_chat_by_contact(self, contact):
        """ return a Chat object, created from the contact.

        @param contact: chat_id (int) or contact object.
        """
        contact_id = getattr(contact, "id", contact)
        assert isinstance(contact_id, int)
        chat_id = capi.lib.dc_create_chat_by_contact_id(
                        self.dc_context, contact_id)
        return Chat(self.dc_context, chat_id)

    def get_message(self, msg_id):
        return Message(self.dc_context, msg_id)

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
        self._evlogger(evt_name, data1, data2)
        method = getattr(self._evhandler, evt_name.lower(), None)
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
