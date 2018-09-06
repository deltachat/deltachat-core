from __future__ import print_function
import deltachat
import re
from deltachat import capi
from deltachat.capi import ffi
import queue


def test_empty_context():
    ctx = capi.lib.dc_context_new(capi.ffi.NULL, capi.ffi.NULL, capi.ffi.NULL)
    capi.lib.dc_close(ctx)


def test_event_defines():
    assert capi.lib.DC_EVENT_INFO == 100


class TestLive:
    def test_basic_configure_login_ok(self, request, tmp_db_path, userpassword):
        q = queue.Queue()
        dc = deltachat.Account(tmp_db_path, logcallback=q.put)
        dc.set_config(addr=userpassword[0], mail_pw=userpassword[1])
        dc.start()
        request.addfinalizer(dc.shutdown)
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
