# External library/SDK source (mounted directories)

The target module often calls into a secure C library, a platform component, or
an SDK that is not checked into the repository. `auto-dtfuzz` can ask the user
for those source directories and scan them read-only. The extra context improves
mock semantics and input constraints; it is not a license to link or execute the
code.

## Inquiry flow

`init`, `mocks list`, `probe`, and `externals inquire` surface
`external_source_questions`:

```json
[
  {
    "kind": "function",
    "symbol": "proto_crc32",
    "signature": "int proto_crc32(const uint8_t *data, size_t len)",
    "status": "excluded_only",
    "question": "proto_crc32 在当前仓库没有可用实现。它是否来自某个安全 C 库..."
  },
  {
    "kind": "include",
    "header": "secure.h",
    "file": "/repo/src/msg_parser.c",
    "question": "msg_parser.c 引用了 secure.h，但当前仓库和已登记的外挂目录中都没有找到..."
  }
]
```

Ask the user once, compactly. If they provide a directory:

```sh
dtfuzz externals add --workdir WORK --path /path/to/library --name secure-c \
  [--include-dir /path/to/include]... [--define NAME=VALUE]... [--std c11]
dtfuzz externals scan --workdir WORK --json
dtfuzz externals list --workdir WORK --json
dtfuzz externals inquire --workdir WORK --json
```

If a **missing external header makes `init` fail before a workspace exists**,
the CLI returns `{"ok": false, "stage": "analyze", "external_source_questions":
[...]}` with a ready-to-run `action`. Register the directory during init:

```sh
dtfuzz init --repo /repo --entry msg_dispatch --source src/msg_parser.c \
  --workdir /repo/.dtfuzz/msg --external-source /path/to/library \
  [--include /path/to/include] --force --json
```

`--external-source` adds the directory (and its include dirs) to the clang
include path so parsing can succeed, and records it in `external_sources` for
context-only scanning. It does **not** link source files.

If the user says the directory is **not** the real implementation (just a
reference), do not pass `--link`.

## What gets scanned

| Category | Detection | Attached to |
| --- | --- | --- |
| Functions | `return_type name(args) { ... }` with balanced-brace body | `external_symbols[].external_source` |
| Macros | `#define NAME value` / `#define NAME(args) ...` | `analysis.external_macros` for macros used by module files |
| Types | `typedef ... NAME;`, `typedef struct ... { } NAME;`, `struct/enum/class NAME`, `using NAME =` | `analysis.external_types` for types referenced by module files |
| Headers | `#include "..."` / `<...>` in module files | `analysis.external_includes` when resolved; `external_source_questions` when missing |

The scanner is plain text parsing (no compiler, no execution, no third-party
Python dependencies). It skips `tests/`, `mock/`, `build/`, etc., and caps file
sizes.

## Matching

- A symbol matches a function definition by `name`, `qualified_name`, or
  `mangled_name`; a short-name fallback handles `netproto::verify_frame` vs
  `verify_frame`.
- Macros and types are attached only when the module source actually references
  the name (word-boundary match), so unrelated library macros do not flood the
  prompt.
- Missing non-system headers become `kind: include` questions.
- System headers (`stdio.h`, `sys/socket.h`, ...) are ignored.

## Context-only by default

Registered sources live in `config.json`:

```json
{
  "external_sources": [
    {
      "name": "secure-c",
      "path": "/opt/secure-c",
      "link": false,
      "include_dirs": ["/opt/secure-c/include"],
      "defines": ["SECURE_API=1"],
      "std": "c11",
      "added_at": "..."
    }
  ]
}
```

They are scanned and shown in prompts/reports, but not compiled.

### Explicit linking

Only when the user confirms the external source is the production
implementation:

```sh
dtfuzz externals add --workdir WORK --path /path/to/library --link ...
# add_source adds the .c/.cc files to sources.real and include dirs, then
# re-runs analysis + probe; resolved symbols have their pending mocks removed.
```

`--link` is a deliberate action. Do not use it for reference code. To remove:

```sh
dtfuzz externals remove --workdir WORK --path /path/to/library
```

By default removal also drops files under that path from `sources.real`;
`--keep-linked` leaves them.

## Where the context is used

- `optimize --mode prompt`: “外部库/平台组件源码（用户提供的外挂目录，只读）”
  section with function/macro/type snippets and resolved headers.
- `constraints draft --mode prompt`: same section, so the four constraint
  classes can cite real library behavior.
- `report.md`: “外部源码/宏/类型” section with matched functions, macros, types,
  and remaining questions.
- `mocks list` / `init` JSON: `external_source_summary` and
  `external_source_questions`.

## Safety

- Scanning reads source text only. No build, no execution.
- The external directory is never linked unless the user explicitly requests
  `--link`; even then it goes through the normal `sources.real` compile/link
  path.
- Do not copy external library bodies into mocks. Cite the definition and write
  a mock rule (or link the real implementation with permission).

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `matched_functions` is 0 | The library defines a different symbol name, or the source uses macros/assembly. Check `externals list` and the report snippets. |
| A function matched but no body | The definition is macro-generated or split across files; the scanner falls back to a signature/snippet. |
| Macro not attached | The module does not reference the macro name, or it is only in a header the module does not include. |
| Missing include question persists | The header name/path does not exist under the registered roots. Add `--include-dir` or the correct library path. |
| `--link` does not remove mocks | Run `dtfuzz probe` after linking; check `probe.resolved`. The external file must compile with the configured include dirs/defines. |
