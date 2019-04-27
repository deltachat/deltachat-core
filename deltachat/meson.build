# This source directory only exists so we can have a
# deltachat/deltachat.h in the build directory.  This allows C code to
# always `#include <deltachat/deltachat.h>` even to build against an
# uninstalled library by -I to point at the build directory.
configure_file(input: '../src/deltachat.h',
               output: 'deltachat.h',
               copy: true,
               install: false)
