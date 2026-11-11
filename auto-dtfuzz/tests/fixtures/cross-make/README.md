# cross-make fixture

A tiny message dispatcher whose Makefile simulates a cross-compiled project:
`CC = arm-linux-gnueabihf-gcc` and ARM-only flags (`-march=armv7-a`,
`-mfloat-abi=hard`, `-mfpu=neon`).  `MSG_PROTO_V2` is defined only in the
Makefile, so a host build that ignores the Makefile cannot parse `src/msg.c`.
