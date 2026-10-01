#!/bin/bash

##brew install llvm   # llvm-strip, llvm-readelf, llvm-size

ZCC="$(pwd)/zig-cc-x86_64-linux-musl"
ls -l "$ZCC"
head -20 "$ZCC"

cd micropython/ports/unix

make VARIANT=minimal clean
rm -f micropython-minimal micropython-minimal.map

unset SDKROOT CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH
make \
  UNAME_S=Linux \
  CC="$ZCC" \
  CPP="$ZCC -E" \
  CXX="$ZCC" \
  STRIP="$(brew --prefix llvm)/bin/llvm-strip" \
  SIZE="$(brew --prefix llvm)/bin/llvm-size" \
  VARIANT=minimal \
  MICROPY_PY_THREAD=0 \
  MICROPY_PY_FFI=0 \
  MICROPY_PY_SOCKET=0 \
  MICROPY_PY_USSL=0 \
  MICROPY_PY_BTREE=0 \
  COPT="-Os -DNDEBUG" \
  CFLAGS_EXTRA="-Wno-error -DMICROPY_GCREGS_SETJMP=1 -DMICROPY_NLR_SETJMP=1 -DMICROPY_USE_READLINE=0" \
  LDFLAGS_ARCH="-Wl,--gc-sections" \
  LDFLAGS_EXTRA="-static -s"
