---
name: auto-dtfuzz
description: >-
  Fuzz a C or C++ module's message-entry function with libFuzzer and drive a
  coverage-guided campaign end to end. Use this skill whenever the user asks to
  fuzz a function/module, mentions dtfuzz, libFuzzer, DT-Fuzz, a "message entry"
  or "message dispatcher", wants a fuzz harness auto-built, needs only the
  functions that cannot be linked to real implementations mocked from human
  rules (random fixed-length bytes, 0/random error codes, custom bodies), or
  wants coverage feedback to automatically raise line/function coverage.
  Also trigger when the user says things like "对这个入口做 fuzz", "给这个模块
  打桩测一下", "消息入口测试", "生成 fuzz 用例", "覆盖率优化", "mock 周边函数",
  even if they only name a function and do not say "fuzz".
---

# dtfuzz: coverage-guided message-entry fuzzing

This skill is a thin orchestration layer over the bundled Python CLI
(`scripts/dtfuzz.sh`). The CLI does deterministic work: full-repo definition
scan, clang AST analysis, link probing, harness generation, mock-code
generation from human rules, compilation, libFuzzer runs, llvm-cov coverage,
crash triage, and a seed/mock optimization loop. Your job is to align with the
user, ask the right questions, choose the right next command, and interpret
results.

The CLI has no third-party Python dependencies. It needs a clang that ships the
libFuzzer runtime and a matching `llvm-cov` / `llvm-profdata`.

## Non-negotiables

- **Never claim coverage without reading `coverage/summary.json`** (or the
  `coverage` object from `round`). Report covered/total and percent.
- **Link real implementations first.** Scan the whole repo for definitions
  (cross-module is expected) and link them. Only functions with no allowed
  implementation are mock candidates.
- **Never use `dt/` or other excluded fakes.** `dt`, `tests`, `test`, `mock(s)`,
  `stub(s)`, and `fake(s)` directories are excluded by default. Do not link
  them, do not copy their bodies. If a symbol exists only there, treat it as
  unlinkable and ask the human for a mock rule.
- **Human mock rules are required.** Pending mocks are not generated; the build
  intentionally fails until a human confirms rules. Do not use `--auto-stub`
  unless the user explicitly asks for a temporary shortcut.
- **Do not silently invent mock semantics.** Ask the user for return/out/random
  behavior, especially when a result controls a branch.
- **Do not modify the target repository's source.** Workspace files live in
  `<repo>/.dtfuzz/<module>/`; mocks live in a separate human-maintainable
  `<repo>/fuzz_mocks/<module>/`. Report findings instead of patching target code.
- **Fuzz only code the user is authorized to test.** Keep libFuzzer resource
  limits on. Do not run network-facing or destructive targets.
- **Never edit generated files by hand.** Change `config.json` or
  `fuzz_mocks/<module>/mocks.json`, then rerun `gen` and `build`. Put custom C
  mock code in `fuzz_mocks/<module>/custom_mocks.c` (or `.cc`).

## Set up the CLI

Resolve the skill directory from this file. In the common install location:

```sh
DTFUZZ="$HOME/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh"
```

If the skill lives elsewhere, use that absolute path. Always pass `--json` to
commands you intend to parse.

```sh
"$DTFUZZ" doctor --json
```

`fuzz_ok` means clang + libFuzzer are usable; `coverage_ok` means
`llvm-cov`/`llvm-profdata` are available for source coverage. **libFuzzer's own
`cov`/`ft`/`corp` feedback always works when `fuzz_ok` is true**, so crash
discovery and corpus growth still work without the source-coverage tools.
`init`/`build`/`round` require `fuzz_ok`; `optimize` and the source-coverage
tables require `coverage_ok`.

`ok: false` means the toolchain is incomplete. If `fuzz_ok` is false, stop and
give the install hint instead of attempting a build:

- macOS: `brew install llvm`, then rerun `doctor`.
- Debian/Ubuntu/WSL: `sudo apt install clang libclang-rt-dev llvm`.
- Fedora: `sudo dnf install clang compiler-rt llvm`.
- Native Windows is not supported; run inside WSL.

## 1. Intake and alignment

Collect these before running `init`:

1. Repository path.
2. Entry function name (the message dispatcher / parser entry).
3. Source file (optional; the CLI can locate a unique definition).
4. Message layout: is there a type/opcode field? Width and endianness? What is
   the buffer and length? Any global init/reset needed?
5. Build environment (WSL/Linux preferred; macOS works with Homebrew LLVM).

If the user only says "给这个模块做 fuzz", locate candidate entries first:

```sh
rg -n "handle|dispatch|parse|recv|on_message|process" "$REPO" --glob '*.{c,cc,cpp,h,hpp}'
```

Then confirm the layout with one compact `AskUserQuestion` (at most 4
questions). Example questions:

- 输入开头是不是消息类型字段？几字节、大端还是小端？
- 缓冲区参数和长度参数分别是哪两个？长度是否包含类型字段？
- 入口是否依赖初始化/全局单例？需要在每个 fuzz 输入前重置什么？
- 仓库里有没有 `dt/`、`mock/`、`stub/`、`fake/` 这类旧实现/假实现目录，绝对不能链接？
- 哪些函数确实无法链接、必须 mock？它们的返回值和 out 参数按什么规则？

Do not guess when the source answers the question; read the source.

## 2. Initialize and analyze

```sh
"$DTFUZZ" init --repo "$REPO" --entry "$ENTRY" [--source "$SRC"] \
  --workdir "$REPO/.dtfuzz/$MODULE" --json
```

Read the JSON summary:

- `entry`: signature, parameter roles, `input_model`, `type_bytes`,
  `type_endian`.
- `target_files`: module sources compiled and measured for coverage.
- `real_files`: cross-module real implementations that will be linked (not
  coverage targets).
- `external_symbols`: only functions with no allowed implementation
  (`missing`, `excluded_only`, `conflict`, `main_only`, `over_cap`).
- `probe`: the result of compiling target+real sources and inspecting undefined
  symbols.
- `pending_mocks`: human mock rules still required.
- `probe.unclassified_symbols`: undefined symbols not matched to an AST call.
  Review them. If they are project functions (function-pointer callbacks,
  assembly references), read the declarations and add them via
  `mocks import` with a complete `signature`/`params`/`return_type`; do not
  invent a signature.
- `mock_questions` / `analysis_questions`: what is worth asking the user.
- `warnings`: e.g. “only defined in dt/, not linked”.

After changing `sources.real`, `sources.exclude`, or `sources.exclude_dirs`,
re-run the link probe:

```sh
"$DTFUZZ" probe --workdir "$WORK" --json
```

If the auto-detected input mapping is wrong (for example the user confirms a
type byte but `input_model` is `buffer`), patch config and regenerate:

```sh
"$DTFUZZ" config set --workdir "$WORK" --patch-json '{
  "entry": {
    "input_model": "typed_buffer",
    "type_bytes": 1,
    "type_endian": "big",
    "params": [
      {"name":"type","type":"uint8_t","role":"msg_type"},
      {"name":"buf","type":"const uint8_t *","role":"buffer"},
      {"name":"len","type":"size_t","role":"buffer_len"}
    ]
  }
}' --json
"$DTFUZZ" gen --workdir "$WORK" --json
```

For an entry that cannot be described by the built-in models (C++ method,
object context, multiple buffers), set `harness.call_expr` in config. `{data}`
and `{size}` are substituted; parameter roles can also be `constant` with
`harness.const_values`.

**Large project with a prebuilt library** (for example OpenSSL's
`libcrypto.a`): use `init --no-real-scan`, set `sources.target` to the files you
want ASan-instrumented, set `sources.libraries` to the prebuilt archive, then
`mocks clear` if the library resolves all symbols. Compile only the target
translation units with ASan; the rest of the library keeps its build flags.
Coverage targets should be the instrumented files only. This avoids rebuilding
or linking the whole dependency graph through source closure.

## 3. Link-first, then human mock rules

`init` already did the expensive part:

1. Scanned the whole repo for definitions, excluding `dt/`, tests, mocks, stubs,
   and fakes by default.
2. Linked every cross-module implementation it found (`real_files`).
3. Compiled target+real sources and probed the link closure for symbols that
   still have no implementation (`probe.unresolved`).
4. Wrote pending mock candidates to
   `<repo>/fuzz_mocks/<module>/mocks.json` — they are **not generated yet**.

```sh
"$DTFUZZ" mocks list --workdir "$WORK" --json
```

For each pending symbol, ask the human for a **structured rule**, not a vague
“return 0”. Useful rule types:

- “return 0 or a random error code”:
  `{"mode":"random_choice","values":["0","-1","-2"]}` or
  `{"mode":"random_error","success":"0","errors":["-1","-2"]}`
- “random fixed-length bytes” (binary out buffer):
  `{"mode":"random_bytes","length":16}`
- “random fixed-length hex string” (ASCII `0-9a-f`, optional NUL):
  `{"mode":"random_hex_string","length":32,"terminate":true}`
- fixed field / fixed value: `{"mode":"set_field","field":"code","value":"0x99"}`
  or `{"mode":"set","value":"-1"}`
- per-call sequence: `return_sequence: ["0","-1","0"]`
- full custom behavior: `body: "...complete C/C++ statements..."`

Write one import file:

```json
{
  "symbols": {
    "crypto_encrypt": {
      "confirmed": true,
      "return": {"mode": "random_choice", "values": ["0", "-1", "-2"]},
      "out_params": {
        "out_buf": {"mode": "random_bytes", "length": 16},
        "out_len": {"mode": "set", "value": "16"}
      }
    },
    "peer_lookup": {
      "confirmed": true,
      "return": {"mode": "random_choice", "values": ["0", "-1"]},
      "out_params": {
        "out": {"mode": "set_field", "field": "code", "value": "0x99"}
      }
    }
  }
}
```

```sh
"$DTFUZZ" mocks import --workdir "$WORK" --file /tmp/mock_rules.json --json
"$DTFUZZ" gen --workdir "$WORK" --json
"$DTFUZZ" build --workdir "$WORK" --json
```

Notes:

- `confirmed: true` is required; unconfirmed entries stay pending and are not
  generated.
- Random rules use a deterministic per-input RNG seeded from the fuzz bytes, so
  crashes remain reproducible while both success/failure paths are explorable.
- `body` can use `dtfuzz_input_byte(i)`, `dtfuzz_input_size()`, `dtfuzz_rand()`,
  `dtfuzz_random_bytes(p, n)`, and `dtfuzz_random_hex(p, n, terminate)`.
- The generated file is `fuzz_mocks/<module>/generated_mocks.c` (or `.cc`).
  Put handwritten code in `fuzz_mocks/<module>/custom_mocks.c` (or `.cc`); it is
  compiled alongside the generated file.
- If the human says a function must always succeed/fail, respect it and record
  that the opposite branch is not reachable in this campaign.
- If a pending symbol actually has a usable implementation that was excluded
  (for example only in `dt/`), do not link it. Ask the user; only if they confirm
  it is production code, add it to `sources.real` or remove its directory from
  `sources.exclude_dirs`.
- `init --force` preserves confirmed user entries; it refreshes pending
  candidates and prunes stale auto entries. If the probe now finds a linked
  real implementation for a confirmed mock, the mock is disabled
  (`stub: false`, `status: resolved_real`) so it cannot duplicate the symbol.

## 4. Build

```sh
"$DTFUZZ" build --workdir "$WORK" --json
```

If it fails:

1. Read `build/build.log`.
2. `build.json` lists `undefined_symbols`, `known_symbols`, and
   `pending_mocks`.
3. Fix include dirs / defines:
   `config set --patch-json '{"sources":{"include_dirs":[...],"defines":[...]}}'`.
4. If a dependency should be real code, add it to `sources.real` and make sure
   it is not excluded. Never add `dt/` or other fake directories.
5. For unresolved symbols, ask the user for mock rules and import them. Do not
   use `--auto-stub` unless the user explicitly requests a temporary shortcut;
   it bypasses their rules.
6. Re-run `gen` and `build` after changing mocks.

Do not loop more than 3 build fixes without involving the user; report the
first real compiler error and what you tried.

## 5. Run and read coverage

```sh
"$DTFUZZ" round --workdir "$WORK" --seconds 60 --json
```

Parse:

- `run.stats`: `cov`, `ft`, `corp` are libFuzzer's own coverage feedback
  (mutation feedback), plus runs/execs and corpus size.
- `coverage.line.percent`, `function.percent`, `branch.percent`.
- `coverage.libfuzzer`: the same `cov`/`ft`/`corp` attached to the source
  coverage summary.
- `coverage.partial_functions` and `uncovered_functions`.
- `coverage.uncovered_lines`, grouped by file.
- `run.crashes`: target-code crashes (deduplicated by sanitizer summary +
  frames). `run.non_target_crashes`: fuzzer/runtime/unclassified artifacts;
  keep them separate in the report.

If `coverage` is `null` and `coverage_error` mentions no `.profraw`, the target
crashed before writing a profile. Inspect `run.crashes`, then use fork mode so
the campaign continues past crashes:

```sh
"$DTFUZZ" round --workdir "$WORK" --seconds 60 --fork --json
```

Fork mode can emit many artifacts; the CLI replays up to
`fuzz.triage_limit` (default 256) and deduplicates by sanitizer summary + top
frames. Raise it for a bug-finding campaign with many distinct crashes.

Coverage is measured only on configured `coverage.target_files`, not the whole
repo. For crash-finding campaigns, some crash-path lines may be missing from
coverage because the fork child aborts; do not classify them as unreachable
without checking the crash list.

## 6. Coverage optimization loop

Repeat until the line target (default 90%), a plateau (default 3 rounds with
<1% improvement), or max rounds (default 10). If the user asks for maximum
coverage, raise `coverage.line_target` to 95 (or 0 to disable the absolute
target and rely on plateau + max rounds) instead of stopping at the default.

```sh
"$DTFUZZ" optimize --workdir "$WORK" --mode prompt --json
```

Read the returned prompt file. It contains uncovered functions/lines, source
snippets, the dictionary, and the current mock bodies. Classify each gap:

1. **Seed-reachable** — magic bytes, length prefixes, nested fields, enum
   values. Produce new seeds/dictionary entries.
2. **Mock-controlled** — a branch guarded by an external return value or
   out-param. Patch that symbol's `body` using `dtfuzz_input_byte`.
3. **Unreachable from this entry** — e.g. a helper called with a hardcoded
   argument. Say so in the report; do not chase it with seeds.

Write one JSON object and import it:

```json
{
  "seeds": [{"hex": "0200054454410000", "reason": "valid length + DTA marker"}],
  "dict": ["DTA", "\\x00\\x07"],
  "mocks": {
    "peer_lookup": {
      "body": "if (!out) return -1; out->code = dtfuzz_input_byte(5) == 0x99 ? 0x99 : 0; return dtfuzz_input_byte(6) & 1 ? 0 : -1;"
    }
  },
  "notes": "optional"
}
```

```sh
"$DTFUZZ" optimize --workdir "$WORK" --mode import --file /tmp/result.json --json
"$DTFUZZ" round --workdir "$WORK" --seconds 60 --json
```

When the import changes mocks, the CLI regenerates and rebuilds automatically.
Seed constraints: even-length hex, no `0x`, respect the input layout, at most
32 seeds and 4096 bytes per seed by default.

If the optimizer proposes a **new mock rule or changes an existing one**, it is
not automatically a human-approved rule. Show the proposed symbol/body/return
semantics to the user, or only apply rules the user already specified. Do not
silently turn a mock into a behavior the user did not describe.

For bulk seeds use `seed add --hex ... --file ...`. For a fully standalone loop:

```sh
"$DTFUZZ" config set --workdir "$WORK" --patch-json '{"optimizer":{"mode":"claude-cli"}}'
"$DTFUZZ" campaign --workdir "$WORK" --seconds 60 --json
```

Prefer prompt mode inside Claude Code to avoid nested LLM calls.

## 7. Crashes and bug-finding campaigns

`run.crashes` contains **target-code** crashes: sanitizer, ASan summary (e.g.
`heap-buffer-overflow file.c:25`), top frames, saved input, and stderr path.
`run.non_target_crashes` contains fuzzer/runtime/unclassified artifacts; do not
report those as project bugs.

Verify each unique target crash, not only the first:

```sh
"$DTFUZZ" repro --workdir "$WORK" --input "$WORK/crashes/<id>/input" --json
```

Use `--fork` when the goal is bug discovery: a non-fork crash stops the process,
while fork mode continues and can surface multiple distinct signatures in one
short campaign. dtfuzz deduplicates by sanitizer summary + top frames, so
heap-buffer-overflow, stack-buffer-overflow, global-buffer-overflow,
heap-use-after-free, double-free, and SEGV are reported separately.

Report the sanitizer, summary (including file:line when symbolized), top frames,
input path, and reproduction command. Call it a sanitizer finding, not a
confirmed vulnerability, unless the user provides severity/impact context. If
coverage is also requested, explain that crash-path lines may be missing because
fork children abort.

## 8. Final report

```sh
"$DTFUZZ" report --workdir "$WORK" --json
```

Present, in Chinese by default:

- Entry signature and input model.
- Line / function / branch coverage with covered/total and target files.
- Uncovered functions/lines and their classification (seed / mock / unreachable).
- Crashes with reproduction command and top frames.
- Mock configuration summary (symbol, return, out params, source).
- Workspace paths: `report.md`, corpus, artifacts, build log.
- Concrete next actions.

If coverage is below target and the loop stopped, say why (plateau, max rounds,
unreachable lines, fixed mock behavior) rather than implying success.

## Reference map

- `references/cli.md` — all commands, config/mocks schema, JSON fields.
- `references/mock-config.md` — out-param modes, sequences, input-dependent
  bodies, worked examples.
- `references/coverage-loop.md` — gap classification, seed strategies, stopping
  rules, common failure modes.
- `references/bug-finding.md` — fork-mode discovery, ASan bug classes, the
  bug-zoo validation, and how to separate target from runtime crashes.
- `references/platforms.md` — macOS/WSL/Linux toolchain setup.
- `references/oss-fuzz-gen-notes.md` — design background and transferable ideas.
