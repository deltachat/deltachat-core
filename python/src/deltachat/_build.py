import distutils.ccompiler
import distutils.sysconfig
import tempfile
import re
from os.path import dirname, abspath
from os.path import join as joinpath

import cffi

here = dirname(abspath(__file__))
deltah = joinpath(dirname(dirname(dirname(here))), "src", "deltachat.h")


def read_event_defines():
    rex = re.compile(r'#define\s+(?:DC_EVENT_|DC_STATE_|DC_CONTACT_ID_|DC_GCL|DC_CHAT)\S+\s+([x\d]+).*')
    return filter(rex.match, open(deltah))


def ffibuilder():
    builder = cffi.FFI()
    builder.set_source(
        'deltachat.capi',
        """
            #include <deltachat/deltachat.h>
            const char * dupstring_helper(const char* string)
            {
                return strdup(string);
            }
            int dc_get_event_signature_types(int e)
            {
                int result = 0;
                if (DC_EVENT_DATA1_IS_STRING(e))
                    result |= 1;
                if (DC_EVENT_DATA2_IS_STRING(e))
                    result |= 2;
                if (DC_EVENT_RETURNS_STRING(e))
                    result |= 4;
                if (DC_EVENT_RETURNS_INT(e))
                    result |= 8;
                return result;
            }
        """,
        libraries=['deltachat'],
    )
    builder.cdef("""
        typedef int... time_t;
        void free(void *ptr);
        extern const char * dupstring_helper(const char* string);
        extern int dc_get_event_signature_types(int);
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
