from __future__ import print_function
import re

try:
    from queue import Queue
except ImportError:
    from Queue import Queue


class TestLive:
    def test_contacts(self, acfactory):
        ac1 = acfactory.get_live_account(started=False)
        contact1 = ac1.create_contact("some1@hello.com", name="some1")
        assert contact1.id
        assert contact1.addr == "some1@hello.com"
        assert contact1.display_name == "some1"
        assert not contact1.is_blocked
        assert not contact1.is_verified

    def test_basic_configure_login_ok(self, acfactory):
        q = Queue()
        ac1 = acfactory.get_live_account(logcallback=q.put)
        imap_ok = smtp_ok = False
        while not imap_ok or not smtp_ok:
            evt_name, data1, data2 = q.get(timeout=5.0)
            print(evt_name, data1, data2)
            if evt_name == "DC_EVENT_ERROR":
                assert 0
            if evt_name == "DC_EVENT_INFO":
                if re.match("imap-login.*ok.", data2.lower()):
                    imap_ok = True
                if re.match("smtp-login.*ok.", data2.lower()):
                    smtp_ok = True
        assert ac1.get_config("mail_pw")
