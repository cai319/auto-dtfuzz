# Platform and toolchain setup

The fuzz target must run on the same host that compiles it. libFuzzer is not a
cross-compiler: an ARM/embedded binary cannot be fuzzed on the host without an
emulator. Run dtfuzz inside WSL/Linux for Linux targets; macOS is suitable for
portable modules and local smoke tests.

## Windows + WSL2

Native Windows is not supported. Install WSL2 Ubuntu, run everything (including
Claude Code) inside WSL, and keep repositories under `~/src`, not `/mnt/c`.
Use `dtfuzz setup --json` for a platform-specific plan and
`dtfuzz setup --install --yes --components base,fi-light` only after reviewing
it. The full step-by-step guide, Fuzz Introspector options, and troubleshooting
are in `setup-wsl2.md`.

## macOS

Apple Command Line Tools clang does not ship the libFuzzer runtime
(`libclang_rt.fuzzer_osx.a`), and Apple's `llvm-cov` may not support the JSON
export the CLI relies on. Install Homebrew LLVM:

```sh
brew install llvm
```

`dtfuzz doctor` prefers `/opt/homebrew/opt/llvm/bin/clang` (or
`/usr/local/opt/llvm/bin/clang`) when it has a fuzzer runtime, and uses the
sibling `llvm-cov`, `llvm-profdata`, `llvm-symbolizer`, and `llvm-cxxfilt`.
Override with `DTFUZZ_CLANG=/path/to/clang` if needed.

Notes:

- Keep clang, llvm-cov, and llvm-profdata from the **same LLVM release**.
- `xcrun --find llvm-cov` points at the Command Line Tools copy; prefer the
  Homebrew copy.
- CMake/ninja are optional: dtfuzz compiles the target sources directly. If the
  project needs generated headers, run its normal build first and add the
  generated include directory via `config set sources.include_dirs`.
- Docker is optional; if installed, a Linux container gives parity with WSL.

## WSL / Linux

Ubuntu/Debian:

```sh
sudo apt update
sudo apt install clang libclang-rt-dev llvm make
```

Fedora:

```sh
sudo dnf install clang compiler-rt llvm make
```

Verify:

```sh
clang --version
clang -print-resource-dir
ls "$(clang -print-resource-dir)"/lib/*/libclang_rt.fuzzer*
llvm-cov --version
llvm-profdata --version
```

If `libclang_rt.fuzzer` is missing, install the matching compiler-rt/fuzzer
package or use the LLVM release tarball. `dtfuzz doctor` reports the exact
missing piece. `doctor.fuzz_ok` is true when clang+libFuzzer are usable;
`doctor.coverage_ok` additionally requires `llvm-cov`/`llvm-profdata`. With only
`fuzz_ok`, campaigns and crash discovery still work using libFuzzer's
`cov`/`ft`/`corp` feedback, but source-coverage tables and `optimize` are
unavailable.

WSL path notes:

- Run dtfuzz from a Linux path (e.g. `~/src/project`), not `/mnt/c/...`, for
  reasonable compile and fuzz throughput.
- Windows-native Python is not supported by this skill; use WSL.
- If the repo lives on Windows, clone/copy it into the WSL filesystem or accept
  slower I/O.

## Build system detection

`init` checks, in order:

1. `compile_commands.json` (root, `build*/`, `cmake-build*/`, `out/**/`) —
   per-file `-I`/`-D`/`-std` flags are reused.
2. `Makefile` / `makefile` / `GNUmakefile`.
3. `CMakeLists.txt`.
4. Meson/Bazel are detected but not parsed; set include dirs/defines manually.

The fuzz build does not invoke the project's build system. It compiles
`sources.target` + `sources.real` + the harness + confirmed mocks with clang.
Definitions are discovered across the repo, but `dt/`, tests, mocks, stubs, and
fakes are excluded by default. Cross-module real implementations are linked;
only symbols with no allowed implementation need human mock rules. This makes
the build predictable, but generated headers/source files from the project build
must already exist. Add their directories to `sources.include_dirs`.

Mock code lives outside `.dtfuzz` in `<repo>/fuzz_mocks/<module>/` so it is
human-maintainable and survives workspace cleanup. Pending entries are not
generated until confirmed.

## Compile flags used

- Compile: `-g -O1 -fno-omit-frame-pointer -fno-common
  -fsanitize=fuzzer-no-link,<sanitizers> -fprofile-instr-generate
  -fcoverage-mapping -std=gnu11|c++17 -I... -D...`
- Link: `-fsanitize=fuzzer,<sanitizers> -fprofile-instr-generate`
- Default sanitizer: `address`. Add `undefined` via
  `config set --patch-json '{"fuzz":{"sanitizers":"address,undefined"}}'`.
- `-fno-sanitize-recover` is not enabled by default; enable it only if the
  project tolerates strict UB checking.

## Resource limits

Defaults: `-max_len=4096 -timeout=10 -rss_limit_mb=2048
-max_total_time=<seconds>`. Adjust per module via `config set fuzz.*`. Use a
smaller `max_len` for fixed-size messages to improve throughput.

## Standalone installation

The CLI can be installed with pipx if desired:

```sh
pipx install /path/to/skill/scripts
dtfuzz doctor
```

Without installation, use the wrapper:

```sh
/path/to/skill/scripts/dtfuzz.sh doctor
```

## Reporting environment issues

If `doctor` is not ok, stop before `init` and report:

- chosen clang path and version;
- whether a fuzzer runtime was found;
- llvm-cov/llvm-profdata paths;
- the exact install command for the current platform.

Do not attempt to compile a fuzz target with a clang that lacks the runtime; the
linker error is confusing and wastes a round.
