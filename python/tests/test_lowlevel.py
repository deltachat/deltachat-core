from __future__ import print_function
from deltachat import capi


def test_empty_context():
    ctx = capi.lib.dc_context_new(capi.ffi.NULL, capi.ffi.NULL, capi.ffi.NULL)
    capi.lib.dc_close(ctx)


def test_event_defines():
    assert capi.lib.DC_EVENT_INFO == 100
