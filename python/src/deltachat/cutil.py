from .capi import lib
from .capi import ffi


def convert_to_bytes_utf8(obj):
    if obj == ffi.NULL:
        return obj
    if not isinstance(obj, bytes):
        return obj.encode("utf8")
    return obj


def iter_array_and_unref(dc_array_t, constructor):
    try:
        for i in range(0, lib.dc_array_get_cnt(dc_array_t)):
            yield constructor(lib.dc_array_get_id(dc_array_t, i))
    finally:
        lib.dc_array_unref(dc_array_t)


def ffi_unicode(obj):
    return ffi.string(obj).decode("utf8")
