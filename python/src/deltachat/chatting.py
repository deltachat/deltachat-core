""" chatting related objects: Contact, Chat, Message. """

import os
from .cutil import as_dc_charpointer, from_dc_charpointer, iter_array
from .capi import lib, ffi
from .types import property_with_doc
from . import const
from datetime import datetime
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

    def delete(self):
        """Delete this chat and all its messages.

        Note:

        - does not delete messages on server
        - the chat or contact is not blocked, new message will arrive
        """
        lib.dc_delete_chat(self._dc_context, self.id)

    # ------  chat status/metadata API ------------------------------

    def is_deaddrop(self):
        """ return true if this chat is a deaddrop chat.

        :returns: True if chat is the deaddrop chat, False otherwise.
        """
        return self.id == const.DC_CHAT_ID_DEADDROP

    def is_promoted(self):
        """ return True if this chat is promoted, i.e.
        the member contacts are aware of their membership,
        have been sent messages.

        :returns: True if chat is promoted, False otherwise.
        """
        return not lib.dc_chat_is_unpromoted(self._dc_chat)

    def get_name(self):
        """ return name of this chat.

        :returns: unicode name
        """
        return from_dc_charpointer(lib.dc_chat_get_name(self._dc_chat))

    def set_name(self, name):
        """ set name of this chat.

        :param: name as a unicode string.
        :returns: None
        """
        name = as_dc_charpointer(name)
        return lib.dc_set_chat_name(self._dc_context, self.id, name)

    # ------  chat messaging API ------------------------------

    def send_text(self, text):
        """ send a text message and return the resulting Message instance.

        :param msg: unicode text
        :raises: ValueError if message can not be send/chat does not exist.
        :returns: the resulting :class:`deltachat.chatting.Message` instance
        """
        msg = as_dc_charpointer(text)
        msg_id = lib.dc_send_text_msg(self._dc_context, self.id, msg)
        if msg_id == 0:
            raise ValueError("message could not be send, does chat exist?")
        return Message(self._dc_context, msg_id)

    def send_file(self, path, mime_type="application/octet-stream"):
        """ send a file and return the resulting Message instance.

        :param path: path to the file.
        :param mime_type: the mime-type of this file, defaults to application/octet-stream.
        :raises: ValueError if message can not be send/chat does not exist.
        :returns: the resulting :class:`deltachat.chatting.Message` instance
        """
        path = as_dc_charpointer(path)
        mtype = as_dc_charpointer(mime_type)
        msg_id = lib.dc_send_file_msg(self._dc_context, self.id, path, mtype)
        if msg_id == 0:
            raise ValueError("message could not be send, does chat exist?")
        return Message(self._dc_context, msg_id)

    def send_image(self, path):
        """ send an image message and return the resulting Message instance.

        :param path: path to an image file.
        :raises: ValueError if message can not be send/chat does not exist.
        :returns: the resulting :class:`deltachat.chatting.Message` instance
        """
        if not os.path.exists(path):
            raise ValueError("path does not exist: {!r}".format(path))
        path = as_dc_charpointer(path)
        msg_id = lib.dc_send_image_msg(self._dc_context, self.id, path, ffi.NULL, 0, 0)
        if msg_id == 0:
            raise ValueError("chat does not exist")
        return Message(self._dc_context, msg_id)

    def get_messages(self):
        """ return list of messages in this chat.

        :returns: list of :class:`deltachat.chatting.Message` objects for this chat.
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
            lib.dc_get_chat_contacts(self._dc_context, self.id),
            lib.dc_array_unref
        )
        return list(iter_array(
            dc_array, lambda id: Contact(self._dc_context, id))
        )


@attr.s
class Message(object):
    """ Message object.

    You obtain instances of it through :class:`deltachat.account.Account` or
    :class:`deltachat.chatting.Chat`.
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

        :returns: :class:`deltachat.chatting.MessageState`
        """
        return MessageState(self)

    @property_with_doc
    def text(self):
        """unicode text of this messages (might be empty if not a text message). """
        return from_dc_charpointer(lib.dc_msg_get_text(self._dc_msg))

    @property_with_doc
    def filename(self):
        """filename if there was an attachment, otherwise empty string. """
        return from_dc_charpointer(lib.dc_msg_get_file(self._dc_msg))

    @property_with_doc
    def basename(self):
        """basename of the attachment if it exists, otherwise empty string. """
        return from_dc_charpointer(lib.dc_msg_get_filename(self._dc_msg))

    @property_with_doc
    def filemime(self):
        """mime type of the file (if it exists)"""
        return from_dc_charpointer(lib.dc_msg_get_filemime(self._dc_msg))

    @property_with_doc
    def type(self):
        """the media type of this message.

        :returns: a :class:`deltachat.chatting.MessageType` instance.
        """
        return MessageType(lib.dc_msg_get_type(self._dc_msg))

    @property_with_doc
    def time_sent(self):
        """time when the message was sent.

        :returns: datetime.datetime() object.
        """
        ts = lib.dc_msg_get_timestamp(self._dc_msg)
        return datetime.fromtimestamp(ts)

    @property
    def chat(self):
        """chat this message was posted in.

        :returns: :class:`deltachat.chatting.Chat` object
        """
        chat_id = lib.dc_msg_get_chat_id(self._dc_msg)
        return Chat(self._dc_context, chat_id)

    def get_sender_contact(self):
        """return the contact of who wrote the message.

        :returns: :class:`deltachat.chatting.Contact` instance
        """
        contact_id = lib.dc_msg_get_from_id(self._dc_msg)
        return Contact(self._dc_context, contact_id)


@attr.s
class MessageType(object):
    """ DeltaChat message type, with is_* methods. """
    _type = attr.ib(validator=v.instance_of(int))
    _mapping = {
            const.DC_MSG_TEXT: 'text',
            const.DC_MSG_IMAGE: 'image',
            const.DC_MSG_GIF: 'gif',
            const.DC_MSG_AUDIO: 'audio',
            const.DC_MSG_VIDEO: 'video',
            const.DC_MSG_FILE: 'file'
    }

    @property_with_doc
    def name(self):
        """ human readable type name. """
        return self._mapping.get(self._type, "")

    def is_text(self):
        """ return True if it's a text message. """
        return self._type == const.DC_MSG_TEXT

    def is_image(self):
        """ return True if it's an image message. """
        return self._type == const.DC_MSG_IMAGE

    def is_gif(self):
        """ return True if it's a gif message. """
        return self._type == const.DC_MSG_GIF

    def is_audio(self):
        """ return True if it's an audio message. """
        return self._type == const.DC_MSG_AUDIO

    def is_video(self):
        """ return True if it's a video message. """
        return self._type == const.DC_MSG_VIDEO

    def is_file(self):
        """ return True if it's a file message. """
        return self._type == const.DC_MSG_FILE


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
        return self._msgstate == const.DC_STATE_IN_FRESH

    def is_in_noticed(self):
        """Return True if Message is incoming and noticed.

        Eg. chat opened but message not yet read - noticed messages
        are not counted as unread but were not marked as read nor resulted in MDNs.
        """
        return self._msgstate == const.DC_STATE_IN_NOTICED

    def is_in_seen(self):
        """Return True if Message is incoming, noticed and has been seen.

        Eg. chat opened but message not yet read - noticed messages
        are not counted as unread but were not marked as read nor resulted in MDNs.
        """
        return self._msgstate == const.DC_STATE_IN_SEEN

    def is_out_pending(self):
        """Return True if Message is outgoing, but is pending (no single checkmark).
        """
        return self._msgstate == const.DC_STATE_OUT_PENDING

    def is_out_failed(self):
        """Return True if Message is unrecoverably failed.
        """
        return self._msgstate == const.DC_STATE_OUT_FAILED

    def is_out_delivered(self):
        """Return True if Message was successfully delivered to the server (one checkmark).

        Note, that already delivered messages may get into the state  is_out_failed().
        """
        return self._msgstate == const.DC_STATE_OUT_DELIVERED

    def is_out_mdn_received(self):
        """Return True if message was marked as read by the recipient(s) (two checkmarks;
        this requires goodwill on the receiver's side). If a sent message changes to this
        state, you'll receive the event DC_EVENT_MSG_READ.
        """
        return self._msgstate == const.DC_STATE_OUT_MDN_RCVD
