# Build modes: direct vs make-host

dtfuzz has two build modes:

| Mode | When to use | How it builds |
| --- | --- | --- |
| `direct` (default) | host-native Makefile/CMake project, or no usable build system | compile discovered target + real sources with clang |
| `make-host` | project Makefile uses a **cross toolchain** (ARM/MIPS/etc.) | introspect the Makefile, replace cross compilers with host clang shims, build host objects + harness |

libFuzzer runs on the host. A cross-compiled firmware binary is not the fuzz
target; the fuzz target is a host binary built from the same sources and
configuration. This is the industry pattern (OSS-Fuzz, Android fuzzing):
production build and fuzz build are separate, but share source/headers/flags.

## make-host flow

```sh
dtfuzz init --repo /repo --entry msg_dispatch --source src/msg.c \
  --workdir /repo/.dtfuzz/msg \
  --build-mode make-host \
  --makefile Makefile \
  [--make-target all] [--make-jobs 8] --json
```

1. `make -f Makefile -Bn <target>` is run (no execution) to recover compile
   commands and their expanded flags.
2. dtfuzz extracts:
   - source files
   - include dirs (`-I`, `-isystem`, `-iquote`)
   - defines (`-D`)
   - `-std=`
   - compiler names
   - target-only flags: `-march`, `-mcpu`, `-mtune`, `-mfpu`, `-mfloat-abi`,
     `-mabi`, `-mthumb`, `-marm`, `--sysroot`, `-target`, `-specs`
3. A compiler shim directory is created under
   `<workdir>/shims/` (never in the repo):
   - `arm-linux-gnueabihf-gcc` → host clang
   - `arm-linux-gnueabihf-g++` → host clang++
   - `ar`/`ranlib` → `llvm-ar`/`llvm-ranlib` when available
   The shim drops target flags and appends sanitizer/coverage flags for `-c`
   commands via `DTFUZZ_EXTRA_CFLAGS`.
4. `make -k -j<make_jobs> <target>` runs with the shim PATH. Firmware link
   steps may fail; objects/libraries are still collected. The log is
   `<workdir>/build/make-host.log`.
5. The fuzz harness itself is compiled with the Makefile-derived flags
   (`flags_by_source`) and linked with clang/libFuzzer. A define that exists
   only in the Makefile (for example `-DMSG_PROTO_V2=1`) is therefore present
   in both the make-host validation and the harness build.

`build.json` records:

```json
{
  "build_mode": "make-host",
  "makefile": "/repo/Makefile",
  "make_host": {
    "ok": true,
    "returncode": 0,
    "target": "all",
    "objects": ["/repo/src/msg.o"],
    "libraries": ["/repo/libmsg.a"],
    "log": "/repo/.dtfuzz/msg/build/make-host.log",
    "shims": {"path": ".../shims", "created": {"arm-linux-gnueabihf-gcc": "..."}}
  }
}
```

## Why not extract function bodies?

Copying functions/macros/structs into the harness:

- loses Makefile-only defines and platform flags;
- loses static/global state and initialization order;
- risks struct layout/ABI/endianness drift;
- produces coverage that does not represent the real code;
- must be re-synced on every upstream change.

Use extraction only for a pure leaf function in a one-off reproduction. For
complex modules, link real sources/objects and mock only at the boundary.

## How mock scope fits

`make-host` still uses the link probe: compile target + real sources + harness,
inspect undefined symbols. A real definition in the repo or a provided external
component source is `must_link`; only `missing` or `excluded_only` symbols are
mockable. See `references/mock-config.md`.

## Architecture-specific code

`make-host` is a host build. Files with inline asm, NEON intrinsics, MMIO, or
RTOS-specific headers may not compile on the host. Options:

1. exclude those TUs and provide host shims for the HAL boundary;
2. keep them out of `sources.target` and document the coverage gap;
3. if target behavior is the thing under test, use an optional cross-clang +
   QEMU mode (slower; sanitizer/coverage limitations). That is not the default.

## Limitations

- Absolute cross-compiler paths cannot be overridden by PATH shims; use a
  Makefile variable (`CC=...`) or a command-rewriting step.
- Makefiles that execute `$(shell $(CC) ...)` at parse time may fail before
  dtfuzz can shim; provide a host variable or a separate host target.
- Generated headers/code must be produced before `make -n` introspection (run
  the project's codegen/host prep first).
- Link scripts, startup files, firmware images, and `objcopy` steps are not
  host targets; only compile commands/objects are consumed.
- A prebuilt third-party `.so` without sanitizer instrumentation still has
  coverage/crash-detection gaps; prefer building it from source with sanitizers.

## Validation checklist

- `dtfuzz doctor --json` → `fuzz_ok/coverage_ok` true.
- `dtfuzz init --build-mode make-host` succeeds and `analysis.makefile` has
  sources/includes/defines/target_flags.
- `make-host.log` shows the cross compiler command and the shim executing clang.
- `build/build.sh` contains Makefile-only defines but **not** `-march`/`-mfpu`.
- `build.json.make_host.ok` is true and objects/libraries are listed.
- `round` produces coverage on the configured target files.
- Report's "构建模式" line shows `make-host` and the Makefile path.
