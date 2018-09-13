from attr import attrs, attrib  # noqa
from attr import validators as v


def attrib_int():
    return attrib(validator=v.instance_of(int))


def attrib_CData():
    from deltachat.capi import ffi
    return attrib(validator=v.instance_of(ffi.CData))


# copied over unmodified from
# https://github.com/devpi/devpi/blob/master/common/devpi_common/types.py
# where it's also tested

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
    return property(get, set)
