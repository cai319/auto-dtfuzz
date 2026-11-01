# Coverage-guided optimization loop

dtfuzz uses **two coverage signals**:

1. **libFuzzer's own feedback** (`cov`, `ft`, `corp` in `run.stats`): sanitizer
   coverage counters drive mutations and corpus growth. This is the signal that
   decides whether libFuzzer keeps an input.
2. **clang source-based coverage** (`-fprofile-instr-generate
   -fcoverage-mapping`): `llvm-profdata merge` turns raw profiles into
   `merged.profdata`; `llvm-cov export` produces JSON; the CLI attributes
   line/function/branch coverage to the configured target files for reporting
   and the optimization prompt.

Both are reported. Source coverage is more interpretable for “which function or
line is missing”; libFuzzer `cov/ft` tells you whether the engine is still
finding new edges/features.

## Reading the summary

```json
{
  "line": {"count": 96, "covered": 91, "percent": 94.79},
  "function": {"count": 6, "covered": 6, "percent": 100.0},
  "branch": {"count": 64, "covered": 60, "percent": 93.75},
  "uncovered_functions": [],
  "partial_functions": [
    {"name": "table_lookup", "file": "src/msg_tables.c", "uncovered_lines": [9,10,11,12,13]}
  ],
  "uncovered_lines": {"src/msg_tables.c": [9,10,11,12,13]}
}
```

Only `coverage.target_files` are measured. `partial_functions` are functions
that ran but have uncovered code regions. Code regions only; expansion, gap and
branch regions are ignored so line ranges are not inflated.

## Classify every gap

Before generating seeds, decide why the line is uncovered:

1. **Seed-reachable.** The path depends on input bytes: magic values, length
   fields, enum/type values, nested TLV headers, checksum bytes, string keys.
   Generate seeds that satisfy all preceding checks and set the target field.
2. **Mock-controlled.** A branch depends on the return value or out-param of a
   symbol that has **no linked implementation**. Seeds cannot change a fixed
   mock. Change the human rule (e.g. `random_choice` return, `random_bytes`
   out-param) or use a `body` with `dtfuzz_input_byte`/`dtfuzz_rand` so the
   fuzzer can discover both sides. If the symbol has a real implementation,
   link it instead of mocking.
3. **Excluded-only.** The only definition lives in `dt/`, tests, mocks, stubs,
   or fakes. Do not link it. Treat the symbol as unlinkable and ask the human
   for a rule; record that the excluded implementation was deliberately not
   used.
4. **Unreachable from this entry.** The code is called with a constant or is
   dead for this entry (e.g. `table_lookup(0x1234)` while the uncovered branch
   is `key == 0x5678`). Report it; do not waste rounds.

If a line is uncovered and the classification is unclear, read the source
snippet in the optimizer prompt. The prompt includes ±N lines around uncovered
regions and the current mock bodies.

## Seed construction rules

- Respect the input model exactly:
  - `buffer`: the whole input is the entry's buffer.
  - `typed_buffer`: `type_offset` bytes reserved, then `type_bytes` in
    `type_endian` order, then the payload; the length parameter is the remaining
    byte count.
- Satisfy **all** checks on the path, not just the last one. Common gates:
  - declared length equals remaining length;
  - magic prefix (`"DTA"`, `0x5A5A`, etc.);
  - minimum/maximum size;
  - checksum/CRC byte;
  - fixed alignment or padding.
- Use the target's endianness. Network protocols are often big-endian even on
  little-endian hosts.
- Keep seeds short. Start from a valid baseline and mutate one field at a time.
- Useful seed families:
  - every message type with an empty payload;
  - each type with a minimal valid header;
  - boundary lengths (0, 1, max, declared length ±1);
  - magic/dictionary tokens at each plausible offset;
  - one seed per branch of a mock-controlled body (for input-dependent mocks).
- Dictionary entries use libFuzzer syntax. Binary bytes are `\xNN`. String
  literals and numeric constants from the target source are auto-extracted; the
  LLM can add protocol tokens.

## Mock construction rules

For each external function whose result controls a condition:

- Prefer an input-dependent body over a constant. Example:

  ```c
  out->code = dtfuzz_input_byte(5) == 0x99 ? 0x99 : 0;
  return (dtfuzz_input_byte(6) & 1) ? 0 : -1;
  ```

- Choose offsets in the **payload** that are not already constrained by a
  validated header/length field. Using a length byte as a mock control byte
  makes the two conditions conflict.
- If the user insists on a fixed behavior, record it and run a second campaign
  later with the opposite behavior to measure both sides. Do not silently flip
  the user's requested semantics.
- After patching mocks, regenerate and rebuild. The import path does this
  automatically when `mocks` is present.

## Optimization prompt

```sh
dtfuzz optimize --workdir DIR --mode prompt --json
```

Returns `optimizer/round-N-prompt.md` and `context.json`. The prompt includes:

- entry signature and input layout;
- current coverage and uncovered functions/lines;
- source snippets around gaps;
- dictionary and current mocks;
- the exact output JSON schema.

Write a single JSON object:

```json
{
  "seeds": [{"hex": "0200054454410000", "reason": "..."}],
  "dict": ["DTA", "\\x00\\x07"],
  "mocks": {
    "peer_lookup": {
      "body": "if (!out) return -1; out->code = ...; return ...;"
    }
  },
  "notes": "..."
}
```

Import it:

```sh
dtfuzz optimize --workdir DIR --mode import --file result.json --json
```

Limits: 32 seeds, 4096 bytes/seed, 128 dict entries, 20 KB mock body. Hex must
be even-length and valid.

## Stopping rules

`campaign` stops when any of these is true:

- line coverage reaches `coverage.line_target` (default 90%; set 95 or 0 when
  the user asks for maximum coverage);
- function coverage reaches `coverage.function_target` (default disabled);
- `coverage.stall_rounds` consecutive rounds improve less than
  `coverage.stall_delta` percent (defaults 3 and 1.0);
- `coverage.max_rounds` reached (default 10);
- build/coverage failure, or `optimizer.mode` is `none`/`prompt` (single round,
  then the agent drives).

The skill should also stop and report when all remaining lines are classified
unreachable or fixed-mock-controlled with no user permission to change them.

## Crashes and fork mode

A crash in non-fork mode terminates libFuzzer and may prevent profile emission.
`round` still returns the run result and `coverage: null`. Use:

```sh
dtfuzz round --workdir DIR --seconds 60 --fork --json
```

Fork mode (`-fork=1 -ignore_crashes=1 ...`) keeps workers running after a crash
and emits profiles. It can produce many `artifacts/crash-*` files; dtfuzz
deduplicates them by sanitizer + top stack frames into `crashes/<id>/`.

## Failure checklist

| Symptom | Check |
| --- | --- |
| `no interesting inputs ... instrumented?` | compile flags must include `-fsanitize=fuzzer-no-link`; the CLI does this; do not reuse a stale binary |
| coverage 0% | target files configured? binary rebuilt after source changes? profile dir writable? |
| corpus never grows | no instrumentation, or harness rejects every input |
| same coverage for many rounds | fixed mocks, unreachable lines, or seeds violate a hard gate |
| `undefined symbol` at link | check `pending_mocks`; get human rules and import them, or add an allowed real source to `sources.real` (never `dt/`) |
| C++ names mangled in reports | toolchain config `llvm_cxxfilt` missing; rerun `init --force` or install `llvm-cxxfilt` |
| crash not reproduced | input may be timeout/OOM, not a sanitizer crash; check `crashes/<id>/stderr.txt` |
| coverage drops after mock patch | mock changed control flow; re-check the body and offsets |
