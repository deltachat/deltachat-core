""" Delta.Chat high level API objects. """

from __future__ import print_function
import threading
import re
import requests
from array import array
try:
    from queue import Queue
except ImportError:
    from Queue import Queue

import deltachat
from . import capi
from .capi import ffi, lib
from .types import cached_property, property_with_doc
import attr
from attr import validators as v


@attr.s
class EventHandler(object):
    dc_context = attr.ib(validator=v.instance_of(ffi.CData))

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
    def __init__(self, dc_context, logid=None, debug=True):
        self.dc_context = dc_context
        self._event_queue = Queue()
        self._debug = debug
        if logid is None:
            logid = str(self.dc_context).strip(">").split()[-1]
        self.logid = logid
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
                 tname, self.logid, evt_name, data1, data2))


@attr.s
class Contact(object):
    """ Delta-Chat Contact. You obtain instances of it through the :class:`Account`.

    :ivar id: integer id of this chat.
    """
    dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @cached_property  # only get it once because we only free it once
    def dc_contact_t(self):
        return capi.lib.dc_get_contact(self.dc_context, self.id)

    def __del__(self, dc_contact_unref=capi.lib.dc_contact_unref):
        if self._property_cache:
            dc_contact_unref(self.dc_contact_t)

    @property_with_doc
    def addr(self):
        """ normalized e-mail address for this account. """
        return ffi_unicode(capi.lib.dc_contact_get_addr(self.dc_contact_t))

    @property_with_doc
    def display_name(self):
        """ display name for this contact. """
        return ffi_unicode(capi.lib.dc_contact_get_display_name(self.dc_contact_t))

    def is_blocked(self):
        """ Return True if the contact is blocked. """
        return capi.lib.dc_contact_is_blocked(self.dc_contact_t)

    def is_verified(self):
        """ Return True if the contact is verified. """
        return capi.lib.dc_contact_is_verified(self.dc_contact_t)


@attr.s
class Chat(object):
    """ Chat object which manages members and through which you can send and retrieve messages.
    """

    dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @cached_property
    def dc_chat_t(self):
        return capi.lib.dc_get_chat(self.dc_context, self.id)

    def __del__(self):
        if self._property_cache:
            capi.lib.dc_chat_unref(self.dc_chat_t)

    def is_deaddrop(self):
        """ return true if this chat is a deaddrop chat. """
        return self.id == lib.DC_CHAT_ID_DEADDROP

    def send_text_message(self, msg):
        """ send a text message and return the resulting Message instance.

        :param msg: unicode text
        :returns: the resulting :class:`Message` instance
        """
        msg = convert_to_bytes_utf8(msg)
        print ("chat id", self.id)
        msg_id = capi.lib.dc_send_text_msg(self.dc_context, self.id, msg)
        return Message(self.dc_context, msg_id)

    def get_messages(self):
        """ return list of messages in this chat.

        :returns: list of Message objects for this chat.
        """
        dc_array_t = lib.dc_get_chat_msgs(self.dc_context, self.id, 0, 0)
        return list(iter_array_and_unref(dc_array_t, lambda x: Message(self.dc_context, x)))

    def count_fresh_messages(self):
        """ return number of fresh messages in this chat.

        :returns: number of fresh messages
        """
        return lib.dc_get_fresh_msg_cnt(self.dc_context, self.id)

    def mark_noticed(self):
        """ mark all messages in this chat as noticed.

        Noticed messages are no longer fresh.
        """
        return lib.dc_marknoticed_chat(self.dc_context, self.id)


@attr.s
class Message(object):
    """ Message object. """
    dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @cached_property
    def dc_msg_t(self):
        return capi.lib.dc_get_msg(self.dc_context, self.id)

    def __del__(self, dc_msg_unref=capi.lib.dc_msg_unref):
        if self._property_cache:
            dc_msg_unref(self.dc_msg_t)

    @property_with_doc
    def text(self):
        """unicode representation. """
        return ffi_unicode(capi.lib.dc_msg_get_text(self.dc_msg_t))

    @property
    def chat(self):
        """chat this message was posted in.

        :returns: :class:`Chat` object
        """
        chat_id = capi.lib.dc_msg_get_chat_id(self.dc_msg_t)
        return Chat(self.dc_context, chat_id)


class Account(object):
    """ An account contains configuration and provides methods
    for configuration, contact and chat creation and manipulation.
    """
    def __init__(self, db_path, logid=None):
        """ initialize account object.

        :param db_path: a path to the account database. The database
                        will be created if it doesn't exist.
        :param logid: an optional logging prefix that should be used with
                      the default internal logging.
        """

        self.dc_context = ctx = capi.lib.dc_context_new(
                                  capi.lib.py_dc_callback,
                                  capi.ffi.NULL, capi.ffi.NULL)
        if hasattr(db_path, "encode"):
            db_path = db_path.encode("utf8")
        capi.lib.dc_open(ctx, db_path, capi.ffi.NULL)
        self._evhandler = EventHandler(self.dc_context)
        self._evlogger = EventLogger(self.dc_context, logid)
        self._threads = IOThreads(self.dc_context)

    def __del__(self, dc_context_unref=capi.lib.dc_context_unref):
        dc_context_unref(self.dc_context)

    def set_config(self, **kwargs):
        """ set configuration values.

        :param kwargs: name=value settings for this account.
                       values need to be unicode.
        :returns: None
        """
        for name, value in kwargs.items():
            name = name.encode("utf8")
            value = value.encode("utf8")
            capi.lib.dc_set_config(self.dc_context, name, value)

    def get_config(self, name):
        """ return unicode string value.

        :param name: configuration key to lookup (eg "addr" or "mail_pw")
        :returns: unicode value
        """
        name = name.encode("utf8")
        res = capi.lib.dc_get_config(self.dc_context, name, b'')
        return ffi_unicode(res)

    def is_configured(self):
        """ determine if the account is configured already.

        :returns: True if account is configured.
        """
        return capi.lib.dc_is_configured(self.dc_context)

    def check_is_configured(self):
        """ Raise ValueError if this account is not configured. """
        if not self.is_configured():
            raise ValueError("need to configure first")

    def get_self_contact(self):
        """ return this account's identity as a :class:`Contact`.

        :returns: :class:`Contact`
        """
        self.check_is_configured()
        return Contact(self.dc_context, capi.lib.DC_CONTACT_ID_SELF)

    def create_contact(self, email, name=ffi.NULL):
        """ Return a :class:`Contact` object.

        :param email: email-address (text type)
        :param name: display name for this contact (optional)
        :returns: :class:`Contact` instance.
        """
        name = convert_to_bytes_utf8(name)
        email = convert_to_bytes_utf8(email)
        contact_id = capi.lib.dc_create_contact(self.dc_context, name, email)
        return Contact(self.dc_context, contact_id)

    def get_contacts(self, query=ffi.NULL, with_self=False, only_verified=False):
        """ return list of :class:`Contact` objects.

        :param query: if a string is specified, only return contacts
                      whose name or e-mail matches query.
        :param only_verified: if true only return verified contacts.
        :param with_self: if true the self-contact is also returned.
        """
        flags = 0
        query = convert_to_bytes_utf8(query)
        if only_verified:
            flags |= lib.DC_GCL_VERIFIED_ONLY
        if with_self:
            flags |= lib.DC_GCL_ADD_SELF
        dc_array_t = lib.dc_get_contacts(self.dc_context, flags, query)
        return list(iter_array_and_unref(dc_array_t, lambda x: Contact(self.dc_context, x)))

    def create_chat_by_contact(self, contact):
        """ return a Chat object with the specified contact.

        :param contact: chat_id (int) or contact object.
        """
        contact_id = getattr(contact, "id", contact)
        assert isinstance(contact_id, int)
        chat_id = capi.lib.dc_create_chat_by_contact_id(
                        self.dc_context, contact_id)
        return Chat(self.dc_context, chat_id)

    def create_chat_by_message(self, message):
        """ return a Chat object for the given message.

        :param message: messsage id or message instance.
        """
        msg_id = getattr(message, "id", message)
        assert isinstance(msg_id, int)
        chat_id = capi.lib.dc_create_chat_by_msg_id(self.dc_context, msg_id)
        return Chat(self.dc_context, chat_id)

    def get_message_by_id(self, msg_id):
        """ return a message object.

        :returns: :class:`Message` instance.
        """
        return Message(self.dc_context, msg_id)

    def mark_seen_messages(self, messages):
        """ mark the given set of messages as seen.

        :param messages: a list of message ids or Message instances.
        """
        arr = array("i")
        for msg in messages:
            msg = getattr(msg, "id", msg)
            arr.append(msg)
        msg_ids = ffi.cast("uint32_t*", ffi.from_buffer(arr))
        lib.dc_markseen_msgs(self.dc_context, msg_ids, len(messages))

    def start(self):
        """ configure this account object, start receiving events,
        start IMAP/SMTP threads. """
        deltachat.set_context_callback(self.dc_context, self._process_event)
        capi.lib.dc_configure(self.dc_context)
        self._threads.start()

    def shutdown(self):
        """ shutdown IMAP/SMTP threads and stop receiving events"""
        deltachat.clear_context_callback(self.dc_context)
        self._threads.stop(wait=True)

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


def convert_to_bytes_utf8(obj):
    if obj == ffi.NULL:
        return obj
    if not isinstance(obj, bytes):
        return obj.encode("utf8")
    return obj


def iter_array_and_unref(dc_array_t, constructor):
    try:
        for i in range(0, lib.dc_array_get_cnt(dc_array_t)):
            yield constructor(lib.dc_array_get_id(dc_array_t, i))
    finally:
        lib.dc_array_unref(dc_array_t)


def ffi_unicode(obj):
    return ffi.string(obj).decode("utf8")
