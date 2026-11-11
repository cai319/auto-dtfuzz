# dtfuzz CLI reference

The CLI entry point is `scripts/dtfuzz.sh` (a wrapper around
`python3 -m dtfuzz`). It is compatible with Python 3.10+ and has no third-party
dependencies. Use `--json` on every command when an agent is parsing output.

## Workspace layout

Tool workspace: `<repo>/.dtfuzz/<module>/`:

| Path | Meaning |
| --- | --- |
| `config.json` | entry, sources, fuzz, coverage, optimizer, toolchain |
| `analysis.json` | full-repo scan + clang AST analysis + link probe summary |
| `harness/fuzz_target.c` or `.cc` | generated libFuzzer harness |
| `harness/dict.txt` | libFuzzer dictionary |
| `corpus/` | seed corpus |
| `build/fuzz_target` | linked fuzz binary |
| `build/build.json`, `build/build.log` | build result and compiler output |
| `build/probe.json`, `build/probe.log` | link probe result |
| `coverage/raw/*.profraw` | raw profiles from the latest run |
| `coverage/summary.json` | normalized coverage result |
| `coverage/history.json` | per-round coverage history |
| `runs/history.json` | per-run stats, crashes, logs |
| `crashes/<id>/` | deduplicated crash input + stderr |
| `artifacts/` | libFuzzer crash/timeout artifacts |
| `optimizer/round-N-*` | prompts, contexts, raw responses |
| `report.md` | generated Markdown report |

Human-maintainable mock directory: `<repo>/fuzz_mocks/<module>/`:

| Path | Meaning |
| --- | --- |
| `mocks.json` | human rules: confirmed symbols, returns, out params, bodies |
| `generated_mocks.c` or `.cc` | generated from confirmed rules only |
| `generated_variables.c` or `.cc` | generated mock globals, if any |
| `custom_mocks.c` / `.cc` | optional handwritten mock code, compiled alongside |
| `dtfuzz_runtime.h` | input/random helpers used by harness and mocks |
| `README.md` | short ownership note |

Pending (unconfirmed) symbols are listed in `mocks.json` but are not emitted to
`generated_mocks.*`; the link fails until a human confirms rules.

## Commands

### doctor

```sh
dtfuzz doctor [--repo PATH] --json
```

Finds a clang with `libclang_rt.fuzzer*`, plus `llvm-cov`, `llvm-profdata`,
`llvm-symbolizer`, `llvm-cxxfilt`, make/cmake/ninja. `fuzz_ok` means clang +
libFuzzer are usable; `coverage_ok` means source coverage tools are present.
`ok` requires both. libFuzzer `cov`/`ft`/`corp` feedback works with `fuzz_ok`
alone; source-coverage tables and `optimize` need `coverage_ok`.

### setup

```sh
dtfuzz setup --json [--components base,fi-light,fi-lto,docker] [--fi-src PATH] [--repo PATH]
dtfuzz setup --install --yes --components base,fi-light
```

Platform-aware setup planner. Default is **plan only**: it reports the detected
OS/WSL/distro, missing tools, and the exact install commands. `--install`
requires `--yes`; `sudo` commands run only when `sudo -n true` succeeds,
otherwise the commands are printed for manual execution.

Components:

- `base` — clang/libFuzzer, llvm-cov/profdata, lld, binutils, git, Python venv.
- `fi-light` — clone fuzz-introspector, create a venv, `pip install -r
  requirements.txt`; use with `introspect --run-light --fi-src ... --fi-python
  <venv>/bin/python`.
- `fi-lto` — optional, heavy: builds a custom LLVM/Clang with the Fuzz
  Introspector pass (Linux + gold).
- `docker` — optional: Docker/OSS-Fuzz helper for generating reports.

Windows is supported only through WSL2. See `references/setup-wsl2.md`.

### init

```sh
dtfuzz init --repo PATH --entry NAME [--source FILE] [--workdir DIR] \
  [--include DIR]... [--define NAME=VALUE]... [--std STD] \
  [--language c|cpp] [--build-system make|cmake|...] [--force] \
  [--build-mode direct|make-host] [--makefile Makefile] \
  [--make-target TARGET] [--make-jobs N] \
  [--no-real-scan] [--introspector REPORT] [--no-introspector] \
  [--external-source DIR]... --json
```

`--build-mode make-host` uses the project Makefile's sources/include dirs/
defines, replaces cross compilers with host clang shims, strips target-only
flags, and validates with `make -k`. It does not copy function bodies. See
`references/build-modes.md`.

`--external-source DIR` registers a user-provided library/SDK source directory
before analysis, adds its root/includes to the clang include path, and scans it
read-only for function/macro/type context. Use it when a missing external
header blocks `init`; it does not link source files. See
`references/external-sources.md`.

`--introspector REPORT` points at a Fuzz Introspector
`fuzzerLogFile-*.data.yaml` or calltree. Without it, `init` auto-discovers
common locations (`out/introspector/`, `build/out/introspector/`,
`introspector/`, `.dtfuzz/*/introspector/`, repo root). `--no-introspector`
disables discovery and uses the AST call graph only.

`--no-real-scan` analyzes only the entry and does not pull in cross-module
sources. Use it for large projects with a prebuilt static/shared library: then
set `sources.target` to the files you actually want instrumented with ASan and
`sources.libraries` to the prebuilt library. `mocks clear` removes all pending
mock entries once the library resolves them.

Runs a full-repo definition scan (excluding `dt/`, tests, mocks, stubs, fakes),
clang AST analysis, cross-module source closure, and a link probe; proposes an
input model; writes `config.json`, `analysis.json`, and
`<repo>/fuzz_mocks/<module>/mocks.json` with **pending** candidates.

`--force` re-runs analysis and the link probe. Confirmed mock entries are kept,
but if the probe now finds a linked real implementation, the mock is disabled
(`stub: false`, `status: resolved_real`) so it cannot duplicate the real symbol.
Pending entries are refreshed/pruned.

Key JSON fields:

- `entry`: `name`, `file`, `header`, `qualified_name`, `return_type`, `params`
  (each with `role`), `input_model`, `type_bytes`, `type_endian`, `type_offset`.
- `target_files`: module sources compiled and measured for coverage.
- `real_files`: cross-module real implementations linked but not coverage
  targets.
- `external_symbols`: only symbols with no allowed implementation; includes
  `status` (`missing`, `excluded_only`, `conflict`, `main_only`, `over_cap`).
- `probe`: `unresolved`, `resolved`, `unclassified_symbols` from the link probe.
- `pending_mocks`: human mock rules still required (reachable symbols only).
- `reachability`: `report`, `format`, `matched`, `entry.matched`,
  `reachable_count`, `module_count`, `external_count`, `stub_scope`, `warnings`.
  Each `stub_scope` item has `symbol`, `status`, `linkage`, `complexity`,
  `signature`, `defined_in`, `excluded_in`, `in_analysis`. Absent when no
  report was used.
- `external_symbols[].reachable` / `.scope`: `reachable`, `unreachable`, or
  `unknown` (not present in the report; kept conservatively).
- `external_symbols[].external_source`: `{file, line, comment, snippet,
  source_name}` when a registered external directory defines the symbol.
- `external_source_summary`: registered dirs, matched functions/macros/types,
  resolved includes, question count.
- `external_source_questions`: `kind: function` / `kind: include` entries to ask
  the user about; also `external_macros`, `external_types`, `external_includes`.
- `mocks_path`, `mock_questions`, `analysis_questions`, `warnings`.

If the probe fails, the candidates fall back to the definition scan and the
warnings explain that build-time link errors are authoritative.

### analyze

```sh
dtfuzz analyze --workdir DIR [--introspector REPORT] [--no-introspector] --json
```

Re-runs clang analysis with the config's source set. With a report, it applies
the reachability filter (calls from explicitly unreachable callers are skipped;
unreachable pending mocks are pruned), re-runs the link probe, and refreshes
`analysis.json` and `introspector/reachability.json`.

### introspect

```sh
dtfuzz introspect --workdir DIR [--report PATH] [--json]
dtfuzz introspect --workdir DIR --run-light --fi-src PATH [--fi-python PATH] [--json]
dtfuzz introspect --workdir DIR --run-lto --fi-clang PATH [--fi-src PATH] [--json]
```

Applies a Fuzz Introspector report to an existing workspace and recomputes the
stub scope. `--run-light` uses fuzz-introspector's source-only tree-sitter
frontend (no custom clang; `linkageType` is empty). `--run-lto` compiles with
the Fuzz Introspector LTO pass (Linux + gold; requires a custom clang from
fuzz-introspector's `build_all.sh`). This re-runs analysis, the link probe, and
the mock merge; see `references/reachability.md`.

### probe

```sh
dtfuzz probe --workdir DIR --json
```

Compiles the target + `sources.real`, inspects `nm` defined/undefined symbols,
and reports `resolved`, `unresolved`, and `unclassified_symbols`. Use after
changing `sources.real`, `sources.exclude`, or `sources.exclude_dirs`.
Resolution matches C++ mangled names, so `netproto::verify_frame` is matched
against `_ZN...`.

`unclassified_symbols` are undefined project-looking symbols that were not
matched to an AST call (for example function-pointer callbacks or assembly
references). They are not auto-mocked because their signature is unknown.
Inspect the declarations and add them with `mocks import` including an explicit
`signature`, `return_type`, and `params`; pending entries without a signature
cannot be generated.

### dt dir exclusion

`sources.exclude_dirs` defaults to:

```
dt, tests, test, mock, mocks, stub, stubs, fake, fakes, fuzz_mocks
```

These directories are not scanned for definitions and not linked. A symbol whose
only definition is in an excluded directory is reported as `excluded_only` and
must be mocked from human rules. Do not copy its implementation. If the user
explicitly confirms a directory is production code, remove it from
`sources.exclude_dirs` (or add the file to `sources.real`).

### config

```sh
dtfuzz config show --workdir DIR --json
dtfuzz config set --workdir DIR --patch-json '{...}' --json
dtfuzz config set --workdir DIR --file patch.json --json
```

`config set` deep-merges the patch into `config.json`. Use it to fix input
mapping, include dirs, defines, real sources, sanitizers, fork mode, coverage
targets, and optimizer mode. Rerun `gen`/`build` after changing build inputs.

### mocks

```sh
dtfuzz mocks list --workdir DIR --json
dtfuzz mocks set --workdir DIR --symbol NAME \
  [--return EXPR] [--return-sequence 'A,B'] \
  [--out-param-json '{"param":{...}}'] [--out-param FILE_OR_JSON] \
  [--body CODE | --body-file FILE] [--no-stub|--stub] [--note TEXT] --json
dtfuzz mocks import --workdir DIR --file patches.json --json
dtfuzz mocks clear --workdir DIR --json
```

`mocks list` shows `confirmed`, `status`, `reachable`, `scope`, `must_link`,
`return`, `return_sequence`, `out_params`, `source`, the mocks path, and any
constraints with `[REVIEW]` / `[OK]` markers. Pending entries are not generated;
unreachable pending entries are pruned during analysis. Symbols with a real
definition are reported under `must_link` and are never emitted.

`mocks set` / `mocks import` refuse symbols with a real definition (repo
non-excluded code or a non-reference external component repo). Link the
implementation instead; only `missing` or `excluded_only` symbols are mockable.

`mocks set` sets `confirmed: true`. `mocks import` accepts either
`{"symbols": {...}}` or a flat symbol map; imported entries are marked
`source: user`, `confirmed: true` unless the patch says otherwise. It also
merges `variables`. Rule examples:

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
    }
  }
}
```

Return modes: `fixed` (`{"value":"0"}`), `random_choice` (`values`),
`random_error` (`success` + `errors`). Out-param modes: `zero`, `fill`, `set`,
`set_field`, `random_bytes`, `random_hex_string`, `raw`.

### constraints

```sh
dtfuzz constraints list --workdir DIR [--category input_construction] [--all] --json
dtfuzz constraints confirm --workdir DIR --id ID [--id ID]... --json
dtfuzz constraints reject  --workdir DIR --id ID [--note TEXT] --json
dtfuzz constraints import  --workdir DIR --file FILE [--source user] [--confirm] --json
dtfuzz constraints draft   --workdir DIR [--mode prompt|claude-cli|anthropic-api|api] --json
dtfuzz constraints draft   --workdir DIR --file RESULT.json --json
```

The four classes are `input_construction`, `variable_constraints`,
`input_relations`, and `setup_teardown`. Drafts are stored with
`confirmed: false` and `review.highlight: true`; `constraints list` prints
`[REVIEW]` for them. Only confirmed items are authoritative in the optimizer
prompt. `setup_teardown` is advisory until the human confirms the exact call
and ordering; then it can be mapped to `harness.init_code` / `reset_code`.

`constraints draft --mode prompt` writes `optimizer/constraints-prompt.md` and
returns its path. Give the prompt to the LLM (or answer it yourself), save the
JSON, then import with `--file` (or `constraints import`). `--file` on the draft
command is the import path.

`mocks import` also accepts a top-level `constraints` object; use
`--confirm-constraints` only for an already-reviewed file. `mocks clear`
preserves constraints.

### externals

```sh
dtfuzz externals add --workdir DIR --path DIR [--name NAME] [--link|--reference-only] \
  [--include-dir DIR]... [--define NAME=VALUE]... [--std STD] --json
dtfuzz externals list   --workdir DIR --json
dtfuzz externals remove --workdir DIR --path DIR [--keep-linked] --json
dtfuzz externals scan   --workdir DIR --json
dtfuzz externals inquire --workdir DIR --json
```

Registers a user-provided library/SDK source directory (mounted/external). The
scanner is read-only: it indexes function definitions, `#define` macros,
typedef/struct/enum types, and module `#include`s. Results are attached to
`analysis.json` and shown in `optimize` / `constraints draft` prompts and
`report.md`. `init`, `mocks list`, `probe`, and `externals inquire` expose
`external_source_questions` for symbols/headers still missing source.

A matched reachable function definition is a **real definition**: it is marked
`must_link`, no mock is created/kept, and `build` fails until it is linked.
`--link` adds the directory's `.c/.cc` files to `sources.real` and its include
dirs/defines to the build config, then re-runs analysis/probe. Use it with
explicit user approval when the directory is the production implementation.

`--reference-only` is the explicit exception for a non-production reference
copy; only then are mocks allowed for symbols defined there. It cannot be
combined with `--link`. `externals remove` unlinks by default; `--keep-linked`
keeps the files in `sources.real`.

### gen

```sh
dtfuzz gen --workdir DIR --json
```

Writes the harness, dictionary, initial seeds, and
`fuzz_mocks/<module>/generated_mocks.c|cc` plus `dtfuzz_runtime.h`. Only
confirmed mock entries are emitted; pending entries appear as comments. It does
not write stubs into `.dtfuzz`.

### build

```sh
dtfuzz build --workdir DIR [--auto-stub] --json
```

Compiles module sources, cross-module `sources.real`, harness, generated mocks,
optional `custom_mocks.c|cc`, and mock variables, then links with
`-fsanitize=fuzzer,<sanitizers>`. Compile flags include
`-fsanitize=fuzzer-no-link,<sanitizers> -fprofile-instr-generate
-fcoverage-mapping`.

On linker failure it parses undefined symbols but does **not** auto-stub by
default. It returns `undefined_symbols`, `known_symbols`, `pending_mocks`, and
`mocks_path`; ask the human for rules, import them, then rerun `gen`/`build`.
`--auto-stub` is an explicit unsafe fallback that fabricates defaults and
bypasses human rules; use only if the user asks for it.

JSON on failure: `stage` (`compile`/`link`), `log`, `undefined_symbols`,
`known_symbols`, `pending_mocks`, `mocks_path`, `suggestion`.

### run / round / coverage

```sh
dtfuzz run --workdir DIR [--seconds N] [--runs N] [--fork] --json
dtfuzz round --workdir DIR [--seconds N] [--runs N] [--fork] --json
dtfuzz coverage --workdir DIR --json
```

`round` = `run` + `coverage`. If a crash prevents profile emission, `round`
returns `coverage: null` and `coverage_error` but still returns the run result.

Run stats include libFuzzer's own feedback (`cov`, `ft`, `corp`), plus `runs`,
`number_of_executed_units`, `average_exec_per_sec`, `new_units_added`,
`peak_rss_mb`, corpus files, and crashes.

`run.crashes` contains target-code crashes only, deduplicated by sanitizer
summary + top frames. `run.non_target_crashes` contains fuzzer/runtime/
unclassified artifacts. `fuzz.triage_limit` (default 256) controls how many
artifacts are replayed; raise it for a bug-finding campaign with many distinct
signatures. Fork mode is recommended for bug discovery because a non-fork crash
terminates the process.

Coverage summary:

- `line`, `function`, `branch`: `{count, covered, percent}`.
- `files`: per-target-file summaries and uncovered line numbers.
- `uncovered_functions`, `partial_functions`: demangled names, file, uncovered
  lines.
- `uncovered_lines`: `{relative-file: [lines]}`.
- `libfuzzer`: `{cov, ft, corp, execs, round_seconds}` — libFuzzer's feedback
  attached to the source coverage.
- `profdata`, `profdata_sha256`, `raw_profiles`, `round`.
- `warning` if target files were not present in llvm-cov output.

### optimize

```sh
dtfuzz optimize --workdir DIR --mode prompt --json
dtfuzz optimize --workdir DIR --mode import --file result.json --json
dtfuzz optimize --workdir DIR --mode claude-cli --json
dtfuzz optimize --workdir DIR --mode anthropic-api --json
```

`prompt` writes `optimizer/round-N-prompt.md` and `context.json` and returns
their paths. `import` applies a JSON result with `seeds`, `dict`, and optional
`mocks` body patches; if mocks changed it regenerates and rebuilds. `claude-cli`
runs `optimizer.claude_cmd` with the prompt on stdin; `anthropic-api` calls the
Messages API with `ANTHROPIC_API_KEY`.

### seed

```sh
dtfuzz seed add --workdir DIR --hex '0200aa' [--hex ...] \
  [--file binary] [--json-file result.json] [--source agent] --json
```

Adds binary seeds to the corpus and records provenance in
`optimizer/seeds.jsonl`.

### campaign

```sh
dtfuzz campaign --workdir DIR [--seconds N] [--max-rounds N] --json
```

Build, run, coverage, optimize, and rebuild if mocks changed. Stop conditions:
line target, function target, stalled coverage, max rounds. With
`optimizer.mode` `none`/`prompt` it performs one round and tells the caller to
run `optimize` itself.

### report / repro / clean

```sh
dtfuzz report --workdir DIR --json
dtfuzz repro --workdir DIR --input INPUT --json
dtfuzz clean --workdir DIR [--all|--build|--coverage|--corpus|--artifacts] --json
```

`report` writes the mandatory five sections and sidecars:

- `report.md` — `报告摘要`, `1. 被测入口与调用链`, `2. 函数级覆盖情况`,
  `3. 打桩函数报告`, `4. 问题列表`, `5. 分析报告与建议`, plus detailed
  appendices.
- `callgraph.json` — entry-reachable call graph (nodes/edges/Mermaid).
- `function_coverage.json` — per-function libFuzzer count and line coverage.
- `stubs.json` — confirmed/pending/blocked stubs with reasons.
- `problems.json` — severity/category/problem/evidence/action.
- `analysis_report.json` — conclusions and recommendations.

See `references/reporting.md`. Rerun `coverage` after the last `round` so the
per-function fields are fresh.

## config.json schema (important fields)

```json
{
  "module": "msg_dispatch",
  "repo": "/abs/repo",
  "language": "c",
  "entry": {
    "name": "msg_dispatch",
    "file": "/abs/repo/src/msg_parser.c",
    "header": "/abs/repo/include/msg_proto.h",
    "qualified_name": "msg_dispatch",
    "return_type": "int",
    "params": [
      {"name": "type", "type": "uint8_t", "role": "msg_type"},
      {"name": "buf", "type": "const uint8_t *", "role": "buffer"},
      {"name": "len", "type": "size_t", "role": "buffer_len"}
    ],
    "input_model": "typed_buffer",
    "type_bytes": 1,
    "type_endian": "big",
    "type_offset": 0,
    "is_method": false
  },
  "sources": {
    "target": ["src/msg_parser.c", "src/msg_tables.c"],
    "real": ["deps/logger.c"],
    "libraries": [],
    "exclude": [],
    "exclude_dirs": ["dt", "tests", "test", "mock", "mocks", "stub", "stubs", "fake", "fakes", "fuzz_mocks"],
    "include_dirs": ["/abs/repo/include"],
    "defines": [],
    "std": "",
    "extra_cflags": [],
    "extra_ldflags": []
  },
  "fuzz": {
    "sanitizers": "address",
    "max_len": 4096,
    "timeout": 10,
    "rss_limit_mb": 2048,
    "seconds_per_round": 60,
    "runs_per_round": 0,
    "use_value_profile": true,
    "fork": false,
    "triage_limit": 256,
    "extra_args": []
  },
  "coverage": {
    "target_files": ["/abs/repo/src/msg_parser.c"],
    "line_target": 90.0,
    "function_target": 0.0,
    "stall_rounds": 3,
    "stall_delta": 1.0,
    "max_rounds": 10
  },
  "optimizer": {
    "mode": "none",
    "model": "",
    "claude_cmd": ["claude", "-p", "--output-format", "json"],
    "max_seeds_per_round": 32,
    "max_seed_bytes": 4096
  },
  "introspector": {
    "report": "",
    "auto": true,
    "fi_clang": "",
    "fi_src": "",
    "python": "python3"
  },
  "build": {
    "mode": "direct",
    "makefile": "Makefile",
    "make_target": "",
    "make_jobs": 0,
    "run_make": true
  },
  "external_sources": [
    {
      "name": "secure-c",
      "path": "/opt/secure-c",
      "link": false,
      "reference_only": false,
      "include_dirs": ["/opt/secure-c/include"],
      "defines": [],
      "std": "",
      "added_at": "..."
    }
  ],
  "harness": {
    "reset_code": "",
    "init_code": "",
    "call_expr": "",
    "const_values": {},
    "extra_includes": []
  },
  "mocks": {
    "enabled": true,
    "dir": "/abs/repo/fuzz_mocks/msg_dispatch",
    "config_file": "",
    "generated_file": "",
    "custom_files": ["custom_mocks.c", "custom_mocks.cc"],
    "auto_stub": false,
    "variables": {}
  }
}
```

`mocks.dir`/`config_file`/`generated_file` are optional overrides. Empty values
mean `<repo>/fuzz_mocks/<module>/`. `auto_stub` is false by default; the CLI
never fabricates mocks unless the caller passes `--auto-stub`.

`introspector.report` pins a Fuzz Introspector report; empty means
auto-discover. `auto` is the discovery switch used by `init`/`analyze`.
`fi_clang`/`fi_src`/`python` are used by `introspect --run-lto` /
`--run-light`. See `references/reachability.md`.

`build.mode` is `direct` (compile discovered sources with clang) or `make-host`
(reuse Makefile sources/include/defines with host clang compiler shims). In
`make-host`, `makefile`/`make_target`/`make_jobs` select the Makefile; `run_make`
controls the `make -k` portability check. See `references/build-modes.md`.

`external_sources` is the user-provided mounted library/SDK registry. Scanning
is read-only, but a matched definition is treated as real: `must_link` blocks
mocking until the source is linked (`--link`) or explicitly marked
`reference_only: true` as a non-production reference. See
`references/external-sources.md`.

`input_model`: `buffer` (whole input is the buffer), `typed_buffer` (first
`type_offset + type_bytes` bytes select the message type), or `custom` (use
`harness.call_expr`).

Parameter roles: `msg_type`, `buffer`, `buffer_len`, `constant`, `custom`.
`constant` values come from `harness.const_values`.

## mocks.json schema

```json
{
  "version": 1,
  "symbols": {
    "peer_lookup": {
      "name": "peer_lookup",
      "qualified_name": "peer_lookup",
      "signature": "int peer_lookup(uint32_t id, Reply * out)",
      "return_type": "int",
      "params": [{"name": "id", "type": "uint32_t"},
                 {"name": "out", "type": "Reply *"}],
      "decl_file": "/abs/repo/include/proto.h",
      "is_method": false,
      "stub": true,
      "confirmed": true,
      "status": "missing",
      "excluded_definition_files": ["/abs/repo/dt/fake_deps.c"],
      "return": {"mode": "random_choice", "values": ["0", "-1"]},
      "return_sequence": [],
      "out_params": {
        "out": {"mode": "set_field", "field": "code", "value": "0x99"}
      },
      "body": "",
      "source": "user",
      "reachable": true,
      "scope": "stub_scope",
      "note": "human rule: fail randomly; always set code 0x99 on success"
    }
  },
  "constraints": {
    "input_construction": [],
    "variable_constraints": [],
    "input_relations": [],
    "setup_teardown": []
  },
  "variables": {
    "g_config": {"type": "struct config", "decl_file": "/abs/repo/include/config.h", "value": "{0}"}
  }
}
```

Keys are `qualified_name`, or `qualified_name@<type>` for overloads.
`confirmed: false` means pending: the entry is listed but not generated, and the
build reports it as unresolved. `source` is one of `pending`, `default`, `auto`,
`user`, `import`, `optimizer`. `reachable`/`scope` are refreshed by
`init`/`analyze`/`introspect`; pending entries with `reachable: false` are
pruned. `init --force` keeps confirmed user entries and refreshes/prunes pending
entries.

Constraint entries have `id`, `category`, `subject`, `requirement`, `reason`,
`evidence`, `applies_to`, `confirmed`, `source`, `status`, `note`, and
`review.highlight`. Drafts are unconfirmed and highlighted; only confirmed
constraints are authoritative. See `references/mock-config.md` for the full
schema.

Return rules:

- `"return": "0"` — fixed expression.
- `{"mode":"fixed","value":"0"}`
- `{"mode":"random_choice","values":["0","-1","-2"]}`
- `{"mode":"random_error","success":"0","errors":["-1","-2"]}`
- `return_sequence` takes precedence and is consumed per call.

Out-param rules:

- `{"mode":"zero","size":"sizeof(*out)"}`
- `{"mode":"fill","size_param":"len","byte":"0x41"}`
- `{"mode":"set","value":"-1"}`
- `{"mode":"set_field","field":"code","value":"0x99"}`
- `{"mode":"random_bytes","length":16}` (binary, fixed length)
- `{"mode":"random_hex_string","length":32,"terminate":true}` (ASCII hex)
- `{"mode":"raw","code":"..."}`

Random rules use a per-input xorshift PRNG seeded from the fuzz bytes, so the
same input always produces the same mock behavior (reproducible crashes) while
different inputs explore success/failure branches.
