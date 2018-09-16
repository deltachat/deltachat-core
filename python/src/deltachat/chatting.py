""" Chatting related objects: Contact, Chat, Message. """

from . import capi
from .cutil import convert_to_bytes_utf8, ffi_unicode, iter_array_and_unref
from .capi import ffi, lib
from .types import cached_property, property_with_doc
import attr
from attr import validators as v


@attr.s
class Contact(object):
    """ Delta-Chat Contact.

    You obtain instances of it through :class:`deltachat.account.Account`.
    """
    dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @cached_property  # only get it once because we only free it once
    def dc_contact_t(self):
        return capi.lib.dc_get_contact(self.dc_context, self.id)

    def __del__(self):
        if lib is not None and hasattr(self, "_property_cache"):
            lib.dc_contact_unref(self.dc_contact_t)

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

    You obtain instances of it through :class:`deltachat.account.Account`.
    """

    dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @cached_property
    def dc_chat_t(self):
        return capi.lib.dc_get_chat(self.dc_context, self.id)

    def __del__(self):
        if lib is not None and hasattr(self, "_property_cache"):
            lib.dc_chat_unref(self.dc_chat_t)

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

        :returns: list of :class:`Message` objects for this chat.
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
    """ Message object.

    You obtain instances of it through :class:`deltachat.account.Account` or
    :class:`Chat`.
    """
    dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @cached_property
    def dc_msg_t(self):
        return capi.lib.dc_get_msg(self.dc_context, self.id)

    def __del__(self):
        if lib is not None and hasattr(self, "_property_cache"):
            lib.dc_msg_unref(self.dc_msg_t)

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
