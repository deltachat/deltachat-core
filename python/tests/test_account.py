from __future__ import print_function
import time
from deltachat.capi import lib


class TestLive:

    def test_selfcontact(self, acfactory):
        ac1 = acfactory.get_live_account(started=False)
        me = ac1.get_self_contact()
        assert me.display_name
        # assert me.addr  # xxx why is this empty?

    def test_contacts(self, acfactory):
        ac1 = acfactory.get_live_account(started=False)
        contact1 = ac1.create_contact(email="some1@hello.com", name="some1")
        assert contact1.id
        assert contact1.addr == "some1@hello.com"
        assert contact1.display_name == "some1"
        assert not contact1.is_blocked
        assert not contact1.is_verified

    def test_chat(self, acfactory):
        ac1 = acfactory.get_live_account(started=False)
        contact1 = ac1.create_contact("some1@hello.com", name="some1")
        chat = ac1.create_chat_by_contact(contact1)
        assert chat.id

    def wait_successful_IMAP_SMTP_connection(self, account):
        imap_ok = smtp_ok = False
        while not imap_ok or not smtp_ok:
            evt_name, data1, data2 = \
                account._evlogger.get_matching("DC_EVENT_(IMAP|SMTP)_CONNECTED")
            if evt_name == "DC_EVENT_IMAP_CONNECTED":
                imap_ok = True
            if evt_name == "DC_EVENT_SMTP_CONNECTED":
                smtp_ok = True
        print("** IMAP and SMTP logins successful", account.dc_context)

    def wait_configuration_progress(self, account, target):
        while 1:
            evt_name, data1, data2 = \
                account._evlogger.get_matching("DC_EVENT_CONFIGURE_PROGRESS")
            if data1 >= target:
                print("** CONFIG PROGRESS {}".format(target), account.dc_context)
                break

    def test_basic_configure_login_ok(self, acfactory):
        ac1 = acfactory.get_live_account()
        self.wait_successful_IMAP_SMTP_connection(ac1)
        self.wait_configuration_progress(ac1, 1000)
        assert ac1.get_config("mail_pw")

    def test_send_message(self, acfactory):
        ac1 = acfactory.get_live_account()
        ac2 = acfactory.get_live_account()
        c2 = ac1.create_contact(email=ac2.get_config("addr"))
        chat = ac1.create_chat_by_contact(c2)
        assert chat.id >= lib.DC_CHAT_ID_LAST_SPECIAL

        self.wait_successful_IMAP_SMTP_connection(ac1)
        self.wait_successful_IMAP_SMTP_connection(ac2)
        self.wait_configuration_progress(ac1, 1000)
        self.wait_configuration_progress(ac2, 1000)
        msgnum = chat.send_text_message("msg1")
        ev = ac1._evlogger.get_matching("DC_EVENT_MSG_DELIVERED")
        evt_name, data1, data2 = ev
        assert data1 == chat.id
        assert data2 == msgnum
        starttime = time.time()
        while time.time() < starttime + 20:
            evt_name, data1, data2 = ac2._evlogger.get_matching("DC_EVENT_INFO")
            if "1 mails read" in data2:
                break
            print("ignoring event", evt_name, data1, data2)
