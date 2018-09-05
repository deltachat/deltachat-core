from __future__ import print_function
import deltachat
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
        q.put((evt, data1, data2))
        return 0
    register_dc_callback(dc_context, cb)

    dbfile = tmpdir.join("test.db")
    capi.lib.dc_open(dc_context, dbfile.strpath, capi.ffi.NULL)
    capi.lib.dc_set_config(dc_context, "addr", userpassword[0])
    capi.lib.dc_set_config(dc_context, "mail_pw", userpassword[1])
    capi.lib.dc_configure(dc_context)

    while 1:
        evt1, data1, data2 = q.get(timeout=1.0)
        if evt1 == capi.lib.DC_EVENT_INFO:
            s = ffi.string(ffi.cast('char*', data2))
            print ("info event", s)
        elif evt1:
            name = get_dc_event_name(evt1)
            print ("other event", name, data1, data2)
