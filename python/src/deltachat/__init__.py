from deltachat import capi


_DC_CALLBACK_MAP = {}
_DC_EVENTNAME_MAP = {}


@capi.ffi.def_extern()
def py_dc_callback(ctx, evt, data1, data2):
    """The global event handler.

    CFFI only allows us to set one global event handler, so this one
    looks up the correct event handler for the given context.
    """
    callback = _DC_CALLBACK_MAP.get(ctx, lambda *a: 0)
    try:
        ret = callback(ctx, evt, data1, data2)
    except:
        ret = 0
    return ret


def get_dc_event_name(integer):
    if not _DC_EVENTNAME_MAP:
        for name, val in vars(capi.lib).items():
            if name.startswith("DC_EVENT_"):
                _DC_EVENTNAME_MAP[val] = name
    return _DC_EVENTNAME_MAP[integer]
