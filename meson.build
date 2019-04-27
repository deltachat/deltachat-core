project(
  'deltachat-core', 'c',
  license: 'GPLv3',
  version: '0.0.0',             # Dummy, see below.
  subproject_dir: 'libs',
  meson_version: '>=0.47.2',
  default_options: ['c_std=gnu99'],
)


## Figure out the version, use this instead of meson.project_version()
# The version schema is:
#  - X.Y.Z for tagged releases.
#  - X.Y.Z990N for dev releases.
#    Where N is the number of commits since the last tag.
version = meson.project_version()
git = find_program('git', required: false)
if git.found()
  git_desc = run_command(git, 'describe', '--tags', '--match=v*')
  if git_desc.returncode() == 0
    git_desc_parts = git_desc.stdout().strip().split('-')
    version = git_desc_parts[0].split('v')[1]
    if git_desc_parts.length() > 1
      version_parts = version.split('.')
      version = '.'.join([version_parts[0],
                          version_parts[1],
                          version_parts[2] + '990' + git_desc_parts[1]])
    endif
  endif
endif
if version == meson.project_version()
  warning('Git version not found, using (dummy) project version')
endif


# pthreads is not a real dependency
pthreads = dependency('threads')

# declare option to link against libm
cc = meson.get_compiler('c')
math = cc.find_library('m')

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
libetpan_fallback = (get_option('monolith')
                     or get_option('force-etpan-fallback')
                     or not libetpan_config.found())

# If we want to use a found etpan version, we have to make sure it's compatible.
# Sadly libetpan doesn't use the same version accross all platforms, so we have
# to check this depending on the platform.
if libetpan_fallback == false
  etpan_version = run_command(libetpan_config, ['--version']).stdout().strip()
  message('Dependency libetpan found: @0@. Checking for compatibility.'.format(etpan_version))
  if (etpan_version.version_compare('>=1.8')
      or build_machine.system() == 'darwin'
      and etpan_version.version_compare('>=1.6'))
    message('Check done. Installed libetpan version is compatible.')
    libetpan_is_compatible = true
  else
    error('Check done. Installed libetpan version is NOT compatible. You need at least 1.9 for most platforms or 1.6 for Darwin/Mac')
  endif
endif

if libetpan_fallback == false
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
else
  if build_machine.system() == 'darwin'
    error('Fallback libetpan not (yet) supported on OSX')
  endif
  message('Using libetpan fallback...')
  etpan_proj = subproject('libetpan', default_options: ['static-pic-lib=true'])
  etpan = etpan_proj.get_variable('dep')
endif


if get_option('rpgp')
  # The rpgp pkg-config file is currently incorrect, so just try
  # linking it instead for now.
  rpgp = dependency('rpgp')
  # rpgp = cc.find_library('rpgp')
  add_project_arguments('-DDC_USE_RPGP', language: 'c')

  netpgp = dependency('', required: false)
else
  rpgp = dependency('', required: false)

  # netpgp is always bundled
  netpgp_proj = subproject('netpgp',
                         default_options: ['static-pic-lib=true',
                                           'bzip2=disabled',
                                           'openssl-idea=disabled',
                                           'openssl-camellia=enabled'])
  netpgp = netpgp_proj.get_variable('dep')
endif

# Provide deltachat/deltachat.h in the build directory
subdir('deltachat')

# Build the library, stored in `lib`.
subdir('src')


# Build the binaries.
subdir('cmdline')


# Finally have some tests
test('stress test', exe, args: ['--stress'])
