project('netpgp', 'c')

zlib = dependency('zlib')
bzip2 = declare_dependency(link_args: '-lbz2')
openssl = dependency('openssl')
pthreads = dependency('threads')

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


lib = library(
  'netpgp', src,
  dependencies: [zlib, bzip2, openssl, pthreads],
  include_directories: inc,
  install: true,
)

dep = declare_dependency(
  include_directories: inc,
  link_with: lib,
)
