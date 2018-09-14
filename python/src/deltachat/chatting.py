""" chatting related objects: Contact, Chat, Message. """

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

    def _refresh(self):
        if hasattr(self, "_property_cache"):
            lib.dc_msg_unref(self.dc_msg_t)
            self._property_cache.clear()

    def __del__(self):
        if lib is not None and hasattr(self, "_property_cache"):
            lib.dc_msg_unref(self.dc_msg_t)

    def get_state(self):
        """ get the message in/out state.

        :returns: :class:`MessageState`
        """
        return MessageState(self)

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


@attr.s
class MessageState(object):
    """ Current Message In/Out state, updated on each call of is_* methods.
    """
    message = attr.ib(validator=v.instance_of(Message))

    @property
    def _msgstate(self):
        self.message._refresh()
        return lib.dc_msg_get_state(self.message.dc_msg_t)

    def is_in_fresh(self):
        """ return True if Message is incoming fresh message (un-noticed).

        Fresh messages are not noticed nor seen and are typically
        shown in notifications.
        """
        return self._msgstate == lib.DC_STATE_IN_FRESH

    def is_in_noticed(self):
        """Return True if Message is incoming and noticed.

        Eg. chat opened but message not yet read - noticed messages
        are not counted as unread but were not marked as read nor resulted in MDNs.
        """
        return self._msgstate == lib.DC_STATE_IN_NOTICED

    def is_in_seen(self):
        """Return True if Message is incoming, noticed and has been seen.

        Eg. chat opened but message not yet read - noticed messages
        are not counted as unread but were not marked as read nor resulted in MDNs.
        """
        return self._msgstate == lib.DC_STATE_IN_SEEN

    def is_out_pending(self):
        """Return True if Message is outgoing, but is pending (no single checkmark).
        """
        return self._msgstate == lib.DC_STATE_OUT_PENDING

    def is_out_failed(self):
        """Return True if Message is unrecoverably failed.
        """
        return self._msgstate == lib.DC_STATE_OUT_FAILED

    def is_out_delivered(self):
        """Return True if Message was successfully delivered to the server (one checkmark).

        Note, that already delivered messages may get into the state  is_out_failed().
        """
        return self._msgstate == lib.DC_STATE_OUT_DELIVERED

    def is_out_mdn_received(self):
        """Return True if message was marked as read by the recipient(s) (two checkmarks;
        this requires goodwill on the receiver's side). If a sent message changes to this
        state, you'll receive the event DC_EVENT_MSG_READ.
        """
        return self._msgstate == lib.DC_STATE_OUT_MDN_RCVD
