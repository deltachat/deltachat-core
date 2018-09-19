""" chatting related objects: Contact, Chat, Message. """

from .cutil import as_dc_charpointer, from_dc_charpointer, iter_array
from .capi import lib, ffi
from .types import property_with_doc
import attr
from attr import validators as v


@attr.s
class Contact(object):
    """ Delta-Chat Contact.

    You obtain instances of it through :class:`deltachat.account.Account`.
    """
    _dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @property
    def _dc_contact(self):
        return ffi.gc(
            lib.dc_get_contact(self._dc_context, self.id),
            lib.dc_contact_unref
        )

    @property_with_doc
    def addr(self):
        """ normalized e-mail address for this account. """
        return from_dc_charpointer(lib.dc_contact_get_addr(self._dc_contact))

    @property_with_doc
    def display_name(self):
        """ display name for this contact. """
        return from_dc_charpointer(lib.dc_contact_get_display_name(self._dc_contact))

    def is_blocked(self):
        """ Return True if the contact is blocked. """
        return lib.dc_contact_is_blocked(self._dc_contact)

    def is_verified(self):
        """ Return True if the contact is verified. """
        return lib.dc_contact_is_verified(self._dc_contact)


@attr.s
class Chat(object):
    """ Chat object which manages members and through which you can send and retrieve messages.

    You obtain instances of it through :class:`deltachat.account.Account`.
    """
    _dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @property
    def _dc_chat(self):
        return ffi.gc(
            lib.dc_get_chat(self._dc_context, self.id),
            lib.dc_chat_unref
        )

    # ------  chat status API ------------------------------

    def is_deaddrop(self):
        """ return true if this chat is a deaddrop chat. """
        return self.id == lib.DC_CHAT_ID_DEADDROP

    def is_promoted(self):
        """ return True if this chat is promoted, i.e.
        the member contacts are aware of their membership,
        have been sent messages.
        """
        return not lib.dc_chat_is_unpromoted(self._dc_chat)

    def get_name(self):
        """ return name of this chat. """
        return from_dc_charpointer(lib.dc_chat_get_name(self._dc_chat))

    def set_name(self, name):
        """ set name of this chat. """
        name = as_dc_charpointer(name)
        return lib.dc_set_chat_name(self._dc_context, self.id, name)

    # ------  chat messaging API ------------------------------

    def send_text_message(self, msg):
        """ send a text message and return the resulting Message instance.

        :param msg: unicode text
        :returns: the resulting :class:`Message` instance
        """
        msg = as_dc_charpointer(msg)
        msg_id = lib.dc_send_text_msg(self._dc_context, self.id, msg)
        return Message(self._dc_context, msg_id)

    def get_messages(self):
        """ return list of messages in this chat.

        :returns: list of :class:`Message` objects for this chat.
        """
        dc_array = ffi.gc(
            lib.dc_get_chat_msgs(self._dc_context, self.id, 0, 0),
            lib.dc_array_unref
        )
        return list(iter_array(dc_array, lambda x: Message(self._dc_context, x)))

    def count_fresh_messages(self):
        """ return number of fresh messages in this chat.

        :returns: number of fresh messages
        """
        return lib.dc_get_fresh_msg_cnt(self._dc_context, self.id)

    def mark_noticed(self):
        """ mark all messages in this chat as noticed.

        Noticed messages are no longer fresh.
        """
        return lib.dc_marknoticed_chat(self._dc_context, self.id)

    # ------  group management API ------------------------------

    def add_contact(self, contact):
        """ add a contact to this chat.

        :params: contact object.
        :exception: ValueError if contact could not be added
        :returns: None
        """
        ret = lib.dc_add_contact_to_chat(self._dc_context, self.id, contact.id)
        if ret != 1:
            raise ValueError("could not add contact {!r} to chat".format(contact))

    def get_contacts(self):
        """ get all contacts for this chat.

        :params: contact object.
        :exception: ValueError if contact could not be added
        :returns: None
        """
        dc_array = ffi.gc(
            lib.dc_get_contacts(self._dc_context, lib.DC_GCL_ADD_SELF, ffi.NULL),
            lib.dc_array_unref
        )
        return list(iter_array(
            dc_array, lambda id: Contact(self._dc_context, id))
        )


@attr.s
class Message(object):
    """ Message object.

    You obtain instances of it through :class:`deltachat.account.Account` or
    :class:`Chat`.
    """
    _dc_context = attr.ib(validator=v.instance_of(ffi.CData))
    id = attr.ib(validator=v.instance_of(int))

    @property
    def _dc_msg(self):
        return ffi.gc(
            lib.dc_get_msg(self._dc_context, self.id),
            lib.dc_msg_unref
        )

    def get_state(self):
        """ get the message in/out state.

        :returns: :class:`MessageState`
        """
        return MessageState(self)

    @property_with_doc
    def text(self):
        """unicode representation. """
        return from_dc_charpointer(lib.dc_msg_get_text(self._dc_msg))

    @property
    def chat(self):
        """chat this message was posted in.

        :returns: :class:`Chat` object
        """
        chat_id = lib.dc_msg_get_chat_id(self._dc_msg)
        return Chat(self._dc_context, chat_id)


@attr.s
class MessageState(object):
    """ Current Message In/Out state, updated on each call of is_* methods.
    """
    message = attr.ib(validator=v.instance_of(Message))

    @property
    def _msgstate(self):
        return lib.dc_msg_get_state(self.message._dc_msg)

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
