# Mock configuration

dtfuzz is **link-first**. It scans the whole repository for definitions and
links every allowed implementation it finds, including cross-module sources. It
only asks for a mock when a symbol still has no allowed implementation after the
link probe.

Excluded by default (`sources.exclude_dirs`):

```
dt, tests, test, mock, mocks, stub, stubs, fake, fakes, fuzz_mocks
```

`dt/` and the other excluded directories are never scanned for definitions and
never linked. A symbol whose only definition lives there is reported as
`excluded_only` and treated as unlinkable. Do not copy its implementation into a
mock. If the user explicitly confirms an excluded directory is production code,
remove it from `sources.exclude_dirs` or add the exact file to `sources.real`.

## Where mocks live

Human-maintainable directory outside `.dtfuzz`:

```
<repo>/fuzz_mocks/<module>/
├── mocks.json                 # source of truth; human rules
├── generated_mocks.c|cc       # generated from confirmed rules only
├── generated_variables.c|cc   # generated mock globals, if any
├── custom_mocks.c|cc          # optional handwritten mocks
├── dtfuzz_runtime.h           # input/random helpers
└── README.md
```

Nothing in this directory is an automatic fake for code that can be linked. A
pending symbol (`confirmed: false`) is listed in `mocks.json` but is **not
emitted**; the build fails with that symbol unresolved until a human confirms a
rule.

## Input constraints (four classes)

`mocks.json` also stores the entry's input contract under `constraints`. These
are not mock code; they are reviewable facts that guide seeds, mock bodies, and
harness setup. The schema follows OSS-Fuzz-Gen's FunctionAnalyzer categories:

```json
{
  "version": 1,
  "constraints": {
    "input_construction": [
      {
        "id": "ic-6f2a87f3",
        "subject": "buf",
        "requirement": "callers use build_packet(): 1-byte type + 2-byte big-endian length + payload",
        "reason": "parse_data reads the declared length first",
        "evidence": "src/msg_parser.c:34",
        "applies_to": "entry",
        "confirmed": false,
        "source": "llm",
        "status": "active",
        "review": {"highlight": true, "note": ""}
      }
    ],
    "variable_constraints": [],
    "input_relations": [],
    "setup_teardown": []
  },
  "symbols": {}
}
```

| Key | Meaning |
| --- | --- |
| `input_construction` | How to build valid arguments/input buffers (builder functions, struct layout, field order). |
| `variable_constraints` | Single-variable constraints: ranges, NUL termination, alignment, enum values, nullability. |
| `input_relations` | Relations across arguments: pointer/size pairs, declared length == payload, type selects a format. |
| `setup_teardown` | Calls/state needed before the entry and cleanup after each input. |

Lifecycle:

1. `dtfuzz constraints draft --mode prompt` writes
   `optimizer/constraints-prompt.md`.
2. The LLM (or the agent) returns a JSON object with a `constraints` section.
3. `dtfuzz constraints draft --file result.json` imports it with
   `confirmed: false` and `review.highlight: true`.
4. `dtfuzz constraints list` shows `[REVIEW]` items.
5. `dtfuzz constraints confirm --id ...` or `reject --id ...` records the human
   decision.

Only confirmed constraints are included as authoritative in the optimizer
prompt's "已确认的输入约束" section. `setup_teardown` is advisory: translate it
into `harness.init_code` / `harness.reset_code` only after the human confirms
the exact call and ordering, then rerun `gen` and `build`.

`mocks import` accepts a top-level `constraints` object alongside `symbols`.
Use `--confirm-constraints` only when the file was already reviewed by a human.
`mocks clear` preserves constraints because they describe the entry, not mock
code.

## Real definitions are never mockable

For every function reachable from the entry (transitive callee closure from AST
+ function-pointer references + Fuzz Introspector), a definition in project
code outside the excluded fake/test dirs — including a user-provided external
component/SDK source directory — must be linked, not mocked.

| Status | Mock allowed? | Action |
| --- | --- | --- |
| `missing` | yes | ask the human for a rule |
| `excluded_only` (only in `dt/`, tests, mocks, stubs, fakes) | yes | ask the human; never copy the excluded body |
| `conflict` (multiple allowed definitions) | **no** | choose a file via `sources.real` / `sources.exclude` |
| `main_only` | **no** | add the allowed definition to `sources.real` |
| `over_cap` | **no** | raise the scan cap / add the file to `sources.real` |
| `external_definition` (provided external repo) | **no** | `externals add --link`, or `--reference-only` only if it is not production code |
| `reference_only` external definition | yes, with explicit user exception | report it |

The CLI enforces this:

- `merge_defaults` does not create pending mocks for real definitions.
- `enforce_real_definitions` disables existing/confirmed mocks
  (`stub: false`, `status: must_link_real`).
- `mocks set` / `mocks import` reject real-definition symbols.
- `render_stubs` never emits them; the generated file lists them as blocked.
- `build` fails with a `must_link` list and a linking suggestion.
- `--auto-stub` skips them.
- Macros/types with real definitions are used from the real headers; do not
  redefine them in `custom_mocks.c` or the harness.

## Human rules

`init` creates pending entries with signatures and call sites. Ask the user for
a structured rule per symbol. Common suggestions:

- “return 0 or a random error code”:
  `{"mode":"random_choice","values":["0","-1","-2"]}` or
  `{"mode":"random_error","success":"0","errors":["-1","-2"]}`
- “random fixed-length hex bytes” (binary out buffer):
  `{"mode":"random_bytes","length":16}`
- “random fixed-length hex string” (ASCII `0-9a-f`):
  `{"mode":"random_hex_string","length":32,"terminate":true}`
- fixed field: `{"mode":"set_field","field":"code","value":"0x99"}`
- fixed return: `{"mode":"fixed","value":"0"}`
- per-call sequence: `return_sequence: ["0","-1","0"]`
- custom behavior: `body: "...complete C/C++ statements..."`

Example import:

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
dtfuzz mocks import --workdir WORK --file rules.json
dtfuzz gen --workdir WORK
dtfuzz build --workdir WORK
```

## Return values

- `"return": "0"` or `{"mode":"fixed","value":"0"}`.
- `{"mode":"random_choice","values":["0","-1","-2"]}` — uniform choice per call.
- `{"mode":"random_error","success":"0","errors":["-1","-2"]}` — success or one
  of the errors.
- `return_sequence` is consumed per call and reset before every input
  (`dtfuzz_reset_mocks`). It covers “first fails, retry succeeds” inside one
  input; it does not let the fuzzer choose the sequence across inputs.
- `void` returns ignore the rule.

Random rules use a deterministic per-input xorshift PRNG seeded from the fuzz
bytes. The same input always produces the same mock behavior (reproducible
crashes), while different inputs explore both success and failure branches.

## Out parameters

`out_params` is keyed by parameter name.

| mode | fields | generated code |
| --- | --- | --- |
| `zero` | `size` (default `sizeof(*p)`) | `if (p) memset(p, 0, size);` |
| `fill` | `size`/`size_param`, optional `byte` | `if (p) memset(p, byte, size);` |
| `set` | `value` | `if (p) *p = value;` |
| `set_field` | `field`, `value` | `if (p) p->field = value;` |
| `random_bytes` | `length`/`size_param`, optional `size` | `if (p) dtfuzz_random_bytes((uint8_t*)p, n);` |
| `random_hex_string` | `length`/`size_param`, `terminate` | `if (p) dtfuzz_random_hex((char*)p, n, terminate);` |
| `raw` | `code` | inserted verbatim |

`random_hex_string` writes `n` ASCII hex characters; with `terminate: true` it
also writes NUL at `p[n]`, so the destination must have `n+1` bytes.

## Custom bodies

`body` is complete statements inserted inside the generated function. It
replaces the generated return/out-param code entirely. Parameter names and types
must match the declaration.

Helpers exposed by the harness (`dtfuzz_runtime.h`):

- `uint8_t dtfuzz_input_byte(size_t i)` — input byte, 0 out of range.
- `size_t dtfuzz_input_size(void)`.
- `uint32_t dtfuzz_rand(void)` — deterministic per-input PRNG.
- `void dtfuzz_rand_seed(uint32_t seed)`.
- `void dtfuzz_random_bytes(uint8_t *p, size_t n)`.
- `void dtfuzz_random_hex(char *p, size_t n, int terminate)`.

Example input-dependent body:

```c
if (!out) return -1;
out->code = dtfuzz_input_byte(5) == 0x99 ? 0x99 : 0;
return (dtfuzz_input_byte(6) & 1) ? 0 : -1;
```

Use payload offsets that are not constrained by a validated header/length field;
otherwise the conditions conflict and the fuzzer cannot satisfy both.

## C and C++ specifics

- C: free functions; include the declaring header.
- C++ namespaces: generated inside the namespace.
- C++ class methods: generated as `Ret Class::method(...)`. Constructors and
  destructors are skipped. Methods with `const`/`noexcept` qualifiers are not
  fully handled; provide a custom body and matching signature, or link the real
  source.
- Overloads are keyed as `qualified_name@<function-type>`.
- Variables: `mocks.variables` can define missing globals, e.g.
  `{"g_config": {"type": "struct config", "value": "{0}"}}`.

## Asking the human

Do not enumerate every external symbol. `init` already lists only the symbols
that the link probe could not resolve. Ask one compact question per symbol (or a
batch of up to four) with concrete options:

> `crypto_encrypt` 无实现。加密输出按“随机定长 16 字节”处理，返回 0 或
> 随机错误码（-1/-2）可以吗？还是固定成功？

If the user says “must always succeed/fail”, respect it and record that the
other side of the branch is not reachable in this campaign. If the user says a
symbol actually has a production implementation, add that file to
`sources.real` — do not use an excluded fake.

`probe.unclassified_symbols` lists undefined project-looking symbols that could
not be matched to an AST call (function-pointer callbacks, assembly references,
etc.). They are not auto-mocked because the signature is unknown. Read the
declaration and add a full entry via `mocks import` (`signature`, `return_type`,
`params`, `confirmed: true`).

## Persistence and re-analysis

- Confirmed entries survive `init --force`; if the link probe now resolves a
  symbol to a real implementation, its mock is disabled (`stub: false`,
  `status: resolved_real`) and not generated. Pending entries are refreshed and
  stale auto entries are pruned.
- Re-run `probe` after changing `sources.real`, `sources.exclude`, or
  `sources.exclude_dirs`.
- After editing mocks, always run `gen` then `build`. `optimize --mode import`
  does this automatically when mock rules change.
- Never hand-edit `generated_mocks.*`; put custom code in `custom_mocks.*`.
