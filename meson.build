project(
  'deltachat-core', 'c',
  license: 'GPLv3',
  subproject_dir: 'libs',
  meson_version: '>=0.47.2',
)

# pthreads is not a real dependency
pthreads = dependency('threads')

# zlib should move grow static-pic-lib support and be handled like
# this as well.
zlib = dependency('zlib', fallback: ['zlib', 'zlib_dep'])

if not get_option('monolith')
  # Normal build, detect dependencies from pkg-config
  openssl = dependency('openssl', fallback: ['openssl', 'dep'])
  sasl = dependency('libsasl2', fallback: ['cyrussasl', 'dep'])
  sqlite = dependency('sqlite3', fallback: ['sqlite', 'dep'])
else
  if get_option('default_library') == 'static'
    error('Can not build a monolith static archive, only shared')
  endif
  # Monolith libdeltachat.so build, use the bundled dependencies.
  subproj_opts = ['static-pic-lib=true']
  openssl_proj = subproject('openssl', default_options: subproj_opts)
  openssl = openssl_proj.get_variable('dep')
  sasl_proj = subproject('cyrussasl', default_options: subproj_opts)
  sasl = sasl_proj.get_variable('dep')
  sqlite_proj = subproject('sqlite', default_options: subproj_opts)
  sqlite = sqlite_proj.get_variable('dep')
endif

# Sadly libetpan does not use pkg-config.  Use the system one if it's
# new enough, if not use a static-pic-lib regardless of
# default-library.
libetpan_config = find_program('libetpan-config', required: false)
if (not get_option('monolith')
    and not get_option('force-etpan-fallback')
    and libetpan_config.found()
    and run_command(libetpan_config, ['--version']).stdout().strip()
                   .version_compare('>=1.8'))
  etpan_version = run_command(libetpan_config, ['--version']).stdout().strip()
  etpan_prefix = run_command(libetpan_config, ['--prefix']).stdout().strip()
  etpan_cflags = run_command(libetpan_config, ['--cflags']).stdout().strip().split()
  etpan_libs = run_command(libetpan_config, ['--libs']).stdout().strip().split()
  etpan_inc_dir = join_paths(etpan_prefix, 'include')
  etpan_inc = include_directories(etpan_inc_dir)
  etpan = declare_dependency(
    compile_args: etpan_cflags,
    include_directories: etpan_inc,
    link_args: etpan_libs,
  )
  message('Dependency libetpan found: @0@'.format(etpan_version))
else
  etpan_proj = subproject('libetpan', default_options: ['static-pic-lib=true'])
  etpan = etpan_proj.get_variable('dep')
endif


# netpgp is always bundled
netpgp_proj = subproject('netpgp')
netpgp = netpgp_proj.get_variable('static_pic_dep')


# Build the library, stored in `lib`.
subdir('src')


# Build the binaries.
subdir('cmdline')


version = run_command('git', 'describe', '--tags')
if version.returncode() != 0
  message('git version not found, pkg-config will not be generated')
else
  pkg = import('pkgconfig')
  pkg.generate(libraries : lib,
               version : version.stdout().strip(),
               subdirs : ['deltachat'],
               name : 'libdeltachat',
               filebase : 'deltachat',
               description : ' Create your own, email-compatible messenger.')
endif
