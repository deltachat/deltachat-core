project(
  'deltachat-core', 'c',
  license: 'GPLv3',
  subproject_dir: 'libs',
)


# These get their information from pkg-config.
zlib = dependency('zlib')
openssl = dependency('openssl')
pthreads = dependency('threads')
sasl = dependency('libsasl2')
sqlite = dependency('sqlite3')

# Sadly libetpan doesn't use pkg-config.
etpan_prefix = run_command('libetpan-config', ['--prefix']).stdout().strip()
etpan_cflags = run_command('libetpan-config', ['--cflags']).stdout().strip().split()
etpan_libs = run_command('libetpan-config', ['--libs']).stdout().strip().split()
etpan_inc_dir = join_paths(etpan_prefix, 'include')
etpan_inc = include_directories(etpan_inc_dir)
if etpan_cflags == ''
  etpan = declare_dependency(
    include_directories: etpan_inc,
    link_args: etpan_libs,
  )
else
  etpan = declare_dependency(
    compile_args: etpan_cflags,
    include_directories: etpan_inc,
    link_args: etpan_libs,
  )
endif

# Build bundled dependencies.
netpgp_proj = subproject('netpgp')
netpgp = netpgp_proj.get_variable('dep')

# Build the library, stored in `lib`.
subdir('src')

# Build the binaries.
subdir('cmdline')


# gen_files = run_command('gen_files.py')
# sources = gen_files.stdout().strip().split('\n')

# gen_includes = run_command('gen_includes.py')
# includes = gen_includes.stdout().strip().split('\n')
# inc = include_directories(includes)

# add_global_arguments(
#   '-Wall',
#   '-fexceptions',
#   '-DHAVE_CONFIG_H',
#   '-DMR_USE_MIME_DEBUG',
#   '-DHAVE_ICONV',
#   '-DSQLITE_OMIT_LOAD_EXTENSION',
#   '-DMR_E2EE_DEFAULT_ENABLED=1',
#   language: 'c',
# )

# lib_src = [
#   'src/mraheader.c',
#   'src/mrapeerstate.c',
#   'src/mrarray.c',
#   'src/mrchat.c',
#   'src/mrchatlist.c',
#   'src/mrcontact.c',
#   'src/mrdehtml.c',
#   'src/mrhash.c',
#   'src/mrimap.c',
#   'src/mrjob.c',
#   'src/mrkey.c',
#   'src/mrkeyring.c',
#   'src/mrloginparam.c',
#   'src/mrlot.c',
#   'src/mrmailbox.c',
#   'src/mrmailbox_configure.c',
#   'src/mrmailbox_e2ee.c',
#   'src/mrmailbox_imex.c',
#   'src/mrmailbox_log.c',
#   'src/mrmailbox_tools.c',
#   'src/mrmimefactory.c',
#   'src/mrmimeparser.c',
#   'src/mrmsg.c',
#   'src/mrosnative.c',
#   'src/mrparam.c',
#   'src/mrpgp.c',
#   'src/mrsaxparser.c',
#   'src/mrsimplify.c',
#   'src/mrsmtp.c',
#   'src/mrsqlite3.c',
#   'src/mrstock.c',
#   'src/mrtools.c',
# ]
# lib_hdr = [
#   'src/mraheader.h',
#   'src/mrapeerstate.h',
#   'src/mrarray.h',
#   'src/mrchat.h',
#   'src/mrchatlist.h',
#   'src/mrcontact.h',
#   'src/mrdehtml.h',
#   'src/mrevent.h',
#   'src/mrhash.h',
#   'src/mrimap.h',
#   'src/mrjob.h',
#   'src/mrkey.h',
#   'src/mrkeyring.h',
#   'src/mrloginparam.h',
#   'src/mrlot.h',
#   'src/mrmailbox.h',
#   'src/mrmailbox_internal.h',
#   'src/mrmimefactory.h',
#   'src/mrmimeparser.h',
#   'src/mrmsg.h',
#   'src/mrosnative.h',
#   'src/mrparam.h',
#   'src/mrpgp.h',
#   'src/mrpoortext.h',
#   'src/mrsaxparser.h',
#   'src/mrsimplify.h',
#   'src/mrsmtp.h',
#   'src/mrsqlite3.h',
#   'src/mrstock.h',
#   'src/mrtools.h',
# ]
# lib_inc = include_directories('src')


# library(
#   'deltachat', lib_src,
#   dependencies: [zlib, openssl, pthreads, sasl, etpan],
#   include_directories: lib_inc,
#   install: true,
# )
# install_headers(
#   lib_hdr,
#   subdir: 'deltachat',
# )
