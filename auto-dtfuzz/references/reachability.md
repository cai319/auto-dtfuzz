# Reachability and stub scope (Fuzz Introspector)

`auto-dtfuzz` uses Fuzz Introspector's static map to decide **which external
functions are worth stubbing**. The AST call graph is still the fallback, but it
scans every function in every compiled file; without reachability it can pull
in calls from code the entry never reaches.

The rule is simple:

> stub scope = functions reachable from the entry **and** not defined in the
> target module **and** unresolved after the link probe.

## Report formats

`dtfuzz` accepts:

| Format | Typical file | Fields used |
| --- | --- | --- |
| Merged report | `fuzzerLogFile-<harness>.data.yaml` | `functionName`, `functionSourceFile`, `functionsReached`, `linkageType`, `CyclomaticComplexity`, `functionLinenumber`, `argNames`/`argTypes`, `returnType` |
| Raw calltree | `fuzzerLogFile-<harness>.data` | indentation tree; no linkage/complexity |
| JSON | a report converted to `{"All functions": {"Elements": [...]}}` or a list | same as YAML |

The parser is a narrow, dependency-free YAML reader for the `All functions:`
list. It ignores `BranchProfiles`, `Callsites`, and other fields it does not
need.

## Generating a report

### 1. OSS-Fuzz / existing CI (most reliable)

```sh
python3 infra/helper.py introspector PROJECT_NAME
```

The introspector output directory contains `fuzzerLogFile-*.data.yaml` and the
calltree. Point `--introspector` at the `.data.yaml` matching the harness that
calls your message entry.

### 2. Fuzz Introspector LTO pass

Build the custom clang from
[fuzz-introspector](https://github.com/ossf/fuzz-introspector):

```sh
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector
./build_all.sh          # builds a clang with the FuzzIntrospector LTO pass
```

Then either compile manually:

```sh
FUZZ_INTROSPECTOR=1 /path/to/fi-clang -flto -g -fuse-ld=gold \
  -fsanitize=fuzzer <sources...> <harness> -o fi_target
```

or ask `dtfuzz` to do it (Linux + gold required):

```sh
dtfuzz introspect --workdir WORK --run-lto \
  --fi-clang /path/to/fi-clang --fi-src /path/to/fuzz-introspector
```

The pass writes raw `.data` files. Fuzz Introspector's frontend converts them
to `.data.yaml`; `--fi-src` is needed for that post-processing step. On macOS
the pass is not available; use a pre-generated report or the light frontend.

### 3. Light frontend (no custom clang)

```sh
dtfuzz introspect --workdir WORK --run-light --fi-src /path/to/fuzz-introspector
```

This runs:

```sh
python3 <fi-src>/src/main.py full --target-dir <repo> --language c-cpp \
  --module-only --out-dir <workdir>/introspector/light --name dtfuzz
```

It needs Fuzz Introspector's Python dependencies (`tree-sitter`, `pyyaml`, ...)
in the selected interpreter. It does not need the LTO pass. The trade-off:
`linkageType` is empty, so `dtfuzz` relies on the link probe for
defined/undefined status.

## Discovery

`init` and `analyze` auto-discover reports unless `--no-introspector` is set:

```
<repo>/out/introspector/*.data.yaml
<repo>/build/out/introspector/*.data.yaml
<repo>/build/out/*/introspector/*.data.yaml
<repo>/introspector/*.data.yaml
<repo>/.dtfuzz/*/introspector/*.data.yaml
<repo>/*.data.yaml
```

Merged `.data.yaml` files are preferred over raw `.data` calltrees. The newest
file wins. Override with `dtfuzz init --introspector PATH` or
`config set '{"introspector":{"report":"PATH"}}'`.

## How the closure is computed

1. Parse every function entry.
2. Demangle names with `llvm-cxxfilt` when available.
3. Find the entry by name: `qualified_name`, `name`, raw/mangled name, and
   short name. If several overloads match, the source file (`entry.file`) picks
   the right one.
4. BFS over `functionsReached` from the entry. `functionsReached` is the list of
   direct callees; the closure is transitive.
5. A callee that is not present in the function list is recorded as a
   **synthetic** reachable node (`known: false`). This happens for library
   leaves and some builtins.
6. Module boundary: a reachable function is `in_module` when its
   `functionSourceFile` matches `analysis.module_files` / `target_files` /
   entry source (exact path, path suffix, or unique basename).
7. External reachable functions are the candidates. `stub_scope` joins them
   with the link probe and records `status`:

| Status | Meaning |
| --- | --- |
| `linked_real` | A real implementation in `sources.real` or `sources.libraries` satisfies it. Do not mock. |
| `excluded_only` | Only defined in an excluded directory (`dt/`, tests, mocks, ...). Needs a human mock rule. |
| `missing` | No definition found. Needs a human mock rule. |
| `conflict` / `main_only` / `over_cap` | Ambiguous or not auto-linked; needs review. |
| `system` | Header/system function; not a project mock candidate. |

## Reachable / unreachable / unknown

Never treat "not in the reachable set" as "unreachable" blindly. The CLI uses
three states:

- **reachable** — the name matches the closure. Normal stub candidate.
- **unreachable** — the name exists in the report but is outside the closure.
  Calls from these callers are skipped, and their pending mocks are pruned.
- **unknown** — the name is absent from the report (indirect call, function
  pointer, assembly, frontend gap). Kept conservatively in the stub scope with
  `scope: unknown`, and a warning is emitted. A missed stub is worse than an
  extra one.

## Applying a report after init

```sh
dtfuzz introspect --workdir WORK --report /path/report.data.yaml --json
```

This re-runs analysis with reachability, re-probes the link closure, prunes
unreachable pending mocks, and writes:

- `analysis.json` → `reachability` summary + `external_symbols[].reachable/scope`
- `introspector/reachability.json` → full closure, module/external split,
  synthetic nodes, stub scope, warnings

`dtfuzz report` includes a "可达性与打桩范围" section and the mock table has
`可达` / `打桩范围` columns.

## JSON shape

```json
{
  "report": "/path/fuzzerLogFile-fuzz_target.data.yaml",
  "format": "data.yaml",
  "matched": true,
  "entry": {"requested": "msg_dispatch", "matched": ["msg_dispatch"]},
  "reachable_count": 11,
  "module_count": 6,
  "external_count": 5,
  "external_functions": [
    {"name": "proto_crc32", "source_file": "<external>", "linkage": "externalLinkage", "complexity": 3}
  ],
  "stub_scope": [
    {"symbol": "proto_crc32", "status": "excluded_only", "signature": "int proto_crc32(const uint8_t *, size_t)"}
  ],
  "warnings": []
}
```

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `entry ... was not found in the report` | The report came from a different harness or source tree. Generate it from a harness that calls the entry, or check `--entry` / `--source`. |
| `reachable_count` is 0 | The entry is not in the report, or the report has no `functionsReached` edges (raw calltree without edges). |
| C++ overloads match the wrong function | Pass `--source src/foo.cpp` or use the qualified name (`ns::dispatch`). |
| `linkageType` is empty everywhere | Light frontend, not the LTO pass. The link probe still determines defined/undefined. |
| Many `unknown` warnings | Function pointers, indirect calls, or a report built from a different translation-unit set. Keep them as conservative stubs and review. |
| No report found | Use `--introspector PATH`, or generate one with `--run-light` / OSS-Fuzz helper. The CLI falls back to the AST call graph and says so. |
