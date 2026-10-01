#!/bin/bash

cd micropython/mpy-cross

CFLAGS_EXTRA="-Wno-error"  make          # native binary - do not use zig here
