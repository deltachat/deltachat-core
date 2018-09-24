project('netpgp', 'c',
        version: '20140220',
        license: '2-part BSD')

# pkg-config dependencies
pthreads = dependency('threads')
zlib = dependency('zlib', fallback: ['zlib', 'zlib_dep'])
openssl = dependency('openssl', fallback: ['openssl', 'dep'])

# Dependencies without pkg-config, just try linking against them
cc = meson.get_compiler('c')

src = [
  'src/compress.c',
  'src/create.c',
  'src/crypto.c',
  'src/keyring.c',
  'src/misc.c',
  'src/openssl_crypto.c',
  'src/packet-parse.c',
  'src/packet-show.c',
  'src/reader.c',
  'src/signature.c',
  'src/symmetric.c',
  'src/validate.c',
  'src/writer.c',
]
inc = include_directories('include')

# We don't own this subproject, silence some warnings
ccargs = []
cc = meson.get_compiler('c')
ccargs += cc.get_supported_arguments(['-Wno-misleading-indentation'])

static_pic_lib = static_library(
  'netpgp', src,
  c_args: ccargs,
  dependencies: [pthreads, zlib, openssl],
  include_directories: inc,
  pic: true,
  install: false,
)

static_pic_dep = declare_dependency(
  include_directories: inc,
  link_with: static_pic_lib,
)
