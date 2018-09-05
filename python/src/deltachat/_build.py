import distutils.ccompiler
import distutils.sysconfig
import tempfile
from os.path import dirname, abspath
from os.path import join as joinpath

import cffi

here = dirname(abspath(__file__))
deltah = joinpath(dirname(dirname(dirname(here))), "src", "deltachat.h")


def read_event_defines():
    for line in open(deltah):
        if line.startswith("#define"):
            parts = line.split()
            if len(parts) >= 3:
                if parts[1].startswith("DC_EVENT"):
                    try:
                        val = int(parts[2])
                    except ValueError:
                        continue
                    yield line


def ffibuilder():
    builder = cffi.FFI()
    builder.set_source(
        'deltachat.capi',
        """
            #include <deltachat/deltachat.h>
        """,
        libraries=['deltachat'],
    )
    builder.cdef("""
        typedef int... time_t;
        void free(void *ptr);
    """)
    cc = distutils.ccompiler.new_compiler(force=True)
    distutils.sysconfig.customize_compiler(cc)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.h') as src_fp:
        src_fp.write('#include <deltachat/deltachat.h>')
        src_fp.flush()
        with tempfile.NamedTemporaryFile(mode='r') as dst_fp:
            cc.preprocess(source=src_fp.name,
                          output_file=dst_fp.name,
                          macros=[('PY_CFFI', '1')])
            builder.cdef(dst_fp.read())
    builder.cdef("""
        extern "Python" uintptr_t py_dc_callback(
            dc_context_t* context,
            int event,
            uintptr_t data1,
            uintptr_t data2);
    """)
    event_defines = "\n".join(read_event_defines())
    builder.cdef(event_defines)
    return builder


if __name__ == '__main__':
    builder = ffibuilder()
    builder.compile(verbose=True)
