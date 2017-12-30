import subprocess
import tempfile

import cffi


ffibuilder = cffi.FFI()
ffibuilder.set_source(
    'deltachat.capi',
    """
    #include <deltachat/mrmailbox.h>
    """,
    libraries=['deltachat'],
)
with tempfile.NamedTemporaryFile(mode='r') as fp:
    proc = subprocess.run(['gcc', '-E', '-o', fp.name, '-DPY_CFFI=1',
                           '../src/mrmailbox.h'])
    proc.check_returncode()
    ffibuilder.cdef(fp.read())


if __name__ == '__main__':
    ffibuilder.compile(verbose=True)
