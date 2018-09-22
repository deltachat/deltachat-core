from __future__ import print_function
import pytest
from deltachat.capi import lib


class TestOfflineAccount:
    def test_is_not_configured(self, acfactory):
        ac1 = acfactory.get_offline_account()
        assert not ac1.is_configured()
        with pytest.raises(ValueError):
            ac1.check_is_configured()

    def test_selfcontact_if_unconfigured(self, acfactory):
        ac1 = acfactory.get_offline_account()
        with pytest.raises(ValueError):
            ac1.get_self_contact()

    # def test_get_config_fails(self, acfactory):
    #    ac1 = acfactory.get_offline_account()
    #    with pytest.raises(KeyError):
    #        ac1.get_config("123123")

    def test_contact_attr(self, acfactory):
        ac1 = acfactory.get_offline_account()
        contact1 = ac1.create_contact(email="some1@hello.com", name="some1")
        assert contact1.id
        assert contact1.addr == "some1@hello.com"
        assert contact1.display_name == "some1"
        assert not contact1.is_blocked()
        assert not contact1.is_verified()

    @pytest.mark.xfail(reason="on travis it fails, needs investigation")
    def test_get_contacts(self, acfactory):
        ac1 = acfactory.get_offline_account()
        contact1 = ac1.create_contact(email="some1@hello.com", name="some1")
        contacts = ac1.get_contacts()
        assert len(contacts) == 1
        assert contact1 in contacts

        assert not ac1.get_contacts(query="some2")
        assert ac1.get_contacts(query="some1")
        assert not ac1.get_contacts(only_verified=True)
        contacts = ac1.get_contacts(with_self=True)
        assert len(contacts) == 2

    def test_chat(self, acfactory):
        ac1 = acfactory.get_offline_account()
        contact1 = ac1.create_contact("some1@hello.com", name="some1")
        chat = ac1.create_chat_by_contact(contact1)
        assert chat.id >= lib.DC_CHAT_ID_LAST_SPECIAL, chat.id

        chat2 = ac1.create_chat_by_contact(contact1.id)
        assert chat2.id == chat.id
        assert chat2.get_name() == chat.get_name()
        assert chat == chat2
        assert not (chat != chat2)

        for ichat in ac1.get_chats():
            if ichat.id == chat.id:
                break
        else:
            pytest.fail("could not find chat")

    def test_group_chat_creation(self, acfactory):
        ac1 = acfactory.get_offline_account()
        contact1 = ac1.create_contact("some1@hello.com", name="some1")
        contact2 = ac1.create_contact("some2@hello.com", name="some2")
        chat = ac1.create_group_chat(name="title1")
        chat.add_contact(contact1)
        chat.add_contact(contact2)
        assert chat.get_name() == "title1"
        assert contact1 in chat.get_contacts()
        assert contact2 in chat.get_contacts()
        assert not chat.is_promoted()
        chat.set_name("title2")
        assert chat.get_name() == "title2"

    def test_message(self, acfactory):
        ac1 = acfactory.get_offline_account()
        contact1 = ac1.create_contact("some1@hello.com", name="some1")
        chat = ac1.create_chat_by_contact(contact1)
        msg = chat.send_text_message("msg1")
        assert msg
        msg_state = msg.get_state()
        assert not msg_state.is_in_fresh()
        assert not msg_state.is_in_noticed()
        assert not msg_state.is_in_seen()
        # XXX the following line should work but doesn't:
        # assert msg_state.is_out_pending()
        assert not msg_state.is_out_failed()
        assert not msg_state.is_out_delivered()
        assert not msg_state.is_out_mdn_received()


class TestOnlineAccount:
    def wait_successful_IMAP_SMTP_connection(self, account):
        imap_ok = smtp_ok = False
        while not imap_ok or not smtp_ok:
            evt_name, data1, data2 = \
                account._evlogger.get_matching("DC_EVENT_(IMAP|SMTP)_CONNECTED")
            if evt_name == "DC_EVENT_IMAP_CONNECTED":
                imap_ok = True
            if evt_name == "DC_EVENT_SMTP_CONNECTED":
                smtp_ok = True
        print("** IMAP and SMTP logins successful", account)

    def wait_configuration_progress(self, account, target):
        while 1:
            evt_name, data1, data2 = \
                account._evlogger.get_matching("DC_EVENT_CONFIGURE_PROGRESS")
            if data1 >= target:
                print("** CONFIG PROGRESS {}".format(target), account)
                break

    def test_selfcontact(self, acfactory):
        ac1 = acfactory.get_live_account()
        self.wait_configuration_progress(ac1, 1000)
        me = ac1.get_self_contact()
        assert me.display_name
        assert me.addr

    def test_basic_configure_login_ok(self, acfactory):
        ac1 = acfactory.get_live_account()
        self.wait_successful_IMAP_SMTP_connection(ac1)
        self.wait_configuration_progress(ac1, 1000)
        assert ac1.get_config("mail_pw")
        assert ac1.is_configured()

    def test_forward_messages(self, acfactory):
        ac1 = acfactory.get_live_account()
        ac2 = acfactory.get_live_account()
        c2 = ac1.create_contact(email=ac2.get_config("addr"))
        chat = ac1.create_chat_by_contact(c2)
        assert chat.id >= lib.DC_CHAT_ID_LAST_SPECIAL

        self.wait_successful_IMAP_SMTP_connection(ac1)
        self.wait_successful_IMAP_SMTP_connection(ac2)
        self.wait_configuration_progress(ac1, 1000)
        self.wait_configuration_progress(ac2, 1000)
        msg_out = chat.send_text_message("message2")

        # wait for other account to receive
        ev = ac2._evlogger.get_matching("DC_EVENT_MSGS_CHANGED")
        assert ev[2] == msg_out.id
        msg_in = ac2.get_message_by_id(msg_out.id)
        assert msg_in.text == "message2"

        # check the message arrived in contact-requests/deaddrop
        chat2 = msg_in.chat
        assert msg_in in chat2.get_messages()
        assert chat2.is_deaddrop()
        assert chat2 == ac2.get_deaddrop_chat()
        chat3 = ac2.create_group_chat("newgroup")
        assert not chat3.is_promoted()
        ac2.forward_messages([msg_in], chat3)
        assert chat3.is_promoted()
        messages = chat3.get_messages()
        ac2.delete_messages(messages)
        assert not chat3.get_messages()

    def test_send_and_receive_message(self, acfactory, lp):
        lp.sec("starting accounts, waiting for configuration")
        ac1 = acfactory.get_live_account()
        ac2 = acfactory.get_live_account()
        c2 = ac1.create_contact(email=ac2.get_config("addr"))
        chat = ac1.create_chat_by_contact(c2)
        assert chat.id >= lib.DC_CHAT_ID_LAST_SPECIAL

        self.wait_successful_IMAP_SMTP_connection(ac1)
        self.wait_successful_IMAP_SMTP_connection(ac2)
        self.wait_configuration_progress(ac1, 1000)
        self.wait_configuration_progress(ac2, 1000)

        lp.sec("sending text message from ac1 to ac2")
        msg_out = chat.send_text_message("message1")
        ev = ac1._evlogger.get_matching("DC_EVENT_MSG_DELIVERED")
        evt_name, data1, data2 = ev
        assert data1 == chat.id
        assert data2 == msg_out.id
        assert msg_out.get_state().is_out_delivered()

        lp.sec("wait for ac2 to receive message")
        ev = ac2._evlogger.get_matching("DC_EVENT_MSGS_CHANGED")
        assert ev[2] == msg_out.id
        msg_in = ac2.get_message_by_id(msg_out.id)
        assert msg_in.text == "message1"

        lp.sec("check the message arrived in contact-requets/deaddrop")
        chat2 = msg_in.chat
        assert msg_in in chat2.get_messages()
        assert chat2.is_deaddrop()
        assert chat2.count_fresh_messages() == 0

        lp.sec("create new chat with contact and verify it's proper")
        chat2b = ac2.create_chat_by_message(msg_in)
        assert not chat2b.is_deaddrop()
        assert chat2b.count_fresh_messages() == 1

        lp.sec("mark chat as noticed")
        chat2b.mark_noticed()
        assert chat2b.count_fresh_messages() == 0

        lp.sec("mark message as seen on ac2, wait for changes on ac1")
        ac2.mark_seen_messages([msg_in])
        lp.step("1")
        ac1._evlogger.get_matching("DC_EVENT_MSG_READ")
        lp.step("2")
        ac1._evlogger.get_info_matching("Message marked as seen")
        assert msg_out.get_state().is_out_mdn_received()
