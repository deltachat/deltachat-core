from __future__ import print_function
import deltachat
import re
import requests
from deltachat import capi, get_dc_event_name
from deltachat.capi import ffi
import queue


def test_empty_context():
    ctx = capi.lib.dc_context_new(capi.ffi.NULL, capi.ffi.NULL, capi.ffi.NULL)
    capi.lib.dc_close(ctx)


def test_event_defines():
    assert capi.lib.DC_EVENT_INFO == 100


def test_cb(register_dc_callback):
    def cb(ctx, evt, data1, data2):
        return 0
    ctx = capi.lib.dc_context_new(capi.lib.py_dc_callback,
                                  capi.ffi.NULL, capi.ffi.NULL)
    register_dc_callback(ctx, cb)
    capi.lib.dc_close(ctx)
    assert deltachat._DC_CALLBACK_MAP[ctx] is cb


def test_basic_events(dc_context, dc_threads, register_dc_callback, tmpdir, userpassword):
    q = queue.Queue()
    def cb(dc_context, evt, data1, data2):
        # the following code relates to the deltachat/_build.py's helper
        # function which provides us signature info of an event call
        event_sig_types = capi.lib.dc_get_event_signature_types(evt)
        if data1 and event_sig_types & 1:
            data1 = ffi.string(ffi.cast('char*', data1))
        if data2 and event_sig_types & 2:
            data2 = ffi.string(ffi.cast('char*', data2))
        evt_name = get_dc_event_name(evt)
        print (evt_name, data1, data2)
        if evt_name == "DC_EVENT_HTTP_GET":
            content =  read_url(data1)
            s = content.encode("utf-8")
            # we need to return a pointer that the core owns
            dupped = capi.lib.dupstring_helper(s)
            return ffi.cast('uintptr_t', dupped)
        elif evt_name == "DC_EVENT_IS_OFFLINE":
            return 0
        elif event_sig_types & (4|8):  # returning string or int means it's a sync event
            print ("dropping sync event: no handler for", evt_name)
            return 0
        # async event
        q.put((evt_name, data1, data2))
        return 0

    register_dc_callback(dc_context, cb)

    dbfile = tmpdir.join("test.db")
    capi.lib.dc_open(dc_context, dbfile.strpath, capi.ffi.NULL)
    capi.lib.dc_set_config(dc_context, "addr", userpassword[0])
    capi.lib.dc_set_config(dc_context, "mail_pw", userpassword[1])
    capi.lib.dc_configure(dc_context)

    imap_ok = smtp_ok = False
    while not imap_ok or not smtp_ok:
        evt_name, data1, data2 = q.get(timeout=5.0)
        if evt_name == "DC_EVENT_ERROR":
            assert 0
        if evt_name == "DC_EVENT_INFO":
            if re.match("imap-login.*ok.", data2.lower()):
                imap_ok = True
            if re.match("smtp-login.*ok.", data2.lower()):
                smtp_ok = True
    assert 0
    # assert capi.lib.dc_imap_is_connected(dc_context)
    # assert capi.lib.dc_smtp_is_connected(dc_context)


def read_url(url):
    try:
        r = requests.get(url)
    except requests.ConnectionError:
        return ''
    else:
        return r.content
