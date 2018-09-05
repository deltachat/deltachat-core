from __future__ import print_function
import deltachat
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
        # print (evt1, data1, data2)
        data1 = try_cast_to_string(data1)
        data2 = try_cast_to_string(data2)
        evt_name = get_dc_event_name(evt)
        print (evt_name, data1, data2)
        if evt_name == "DC_EVENT_HTTP_GET":
            content =  read_url(data1)
            # XXX how to give this string back to delta-core properly?
            # for now we just return nothing
        else:
            q.put((evt_name, data1, data2))
        return 0
    register_dc_callback(dc_context, cb)

    dbfile = tmpdir.join("test.db")
    capi.lib.dc_open(dc_context, dbfile.strpath, capi.ffi.NULL)
    capi.lib.dc_set_config(dc_context, "addr", userpassword[0])
    capi.lib.dc_set_config(dc_context, "mail_pw", userpassword[1])
    capi.lib.dc_configure(dc_context)

    while 1:
        evt_name, data1, data2 = q.get(timeout=2.0)
        if evt_name == "DC_EVENT_ERROR":
            assert 0
        # XXX look for successful termination once we make things pass


def read_url(url):
    try:
        r = requests.get(url)
    except requests.ConnectionError:
        pass
    else:
        return r.content


def try_cast_to_string(obj):
    if isinstance(obj, long):
        if obj > 100000:
            return ffi.string(ffi.cast('char*', obj))
    # print ("failed to convert", repr(obj))
    return obj
