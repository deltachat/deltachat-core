from .capi import lib


def property_with_doc(f):
    return property(f, None, None, f.__doc__)


class _UnrefStruct(object):
    def __init__(self, c_obj):
        self.p = c_obj

    def __del__(self):
        obj = self.__dict__.pop("p", None)
        if lib is not None and obj is not None:
            self._unref(obj)


class DC_Context(_UnrefStruct):
    _unref = lib.dc_context_unref


class DC_Contact(_UnrefStruct):
    _unref = lib.dc_contact_unref


class DC_Chat(_UnrefStruct):
    _unref = lib.dc_chat_unref


class DC_Msg(_UnrefStruct):
    _unref = lib.dc_msg_unref


# copied over unmodified from
# https://github.com/devpi/devpi/blob/master/common/devpi_common/types.py

def cached_property(f):
    """returns a cached property that is calculated by function f"""
    def get(self):
        try:
            return self._property_cache[f]
        except AttributeError:
            self._property_cache = {}
        except KeyError:
            pass
        x = self._property_cache[f] = f(self)
        return x

    def set(self, val):
        propcache = self.__dict__.setdefault("_property_cache", {})
        propcache[f] = val

    def fdel(self):
        propcache = self.__dict__.setdefault("_property_cache", {})
        del propcache[f]

    return property(get, set, fdel)
