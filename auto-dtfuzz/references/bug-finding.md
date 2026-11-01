# Bug-finding campaigns

dtfuzz runs libFuzzer with AddressSanitizer by default
(`-fsanitize=fuzzer-no-link,address` compile, `-fsanitize=fuzzer,address` link).
Add `undefined` via:

```sh
dtfuzz config set --workdir WORK --patch-json '{"fuzz":{"sanitizers":"address,undefined"}}'
```

libFuzzer's `cov`/`ft` counters drive corpus growth; ASan/UBSan turn memory bugs
into process aborts, which libFuzzer saves as artifacts.

## Use fork mode for discovery

A non-fork crash terminates the process. For bug discovery:

```sh
dtfuzz round --workdir WORK --seconds 60 --fork --json
```

Fork mode keeps workers running after crashes (`-ignore_crashes=1`,
`-ignore_timeouts=1`, `-ignore_ooms=1`) and can surface multiple distinct bugs in
one campaign. The CLI replays artifacts up to `fuzz.triage_limit` (default 256)
and deduplicates by **sanitizer summary + top frames**, so distinct bugs in the
same function are not collapsed when the summary includes different
`file:line` or sanitizer classes.

- `run.crashes`: target-code findings. Report these.
- `run.non_target_crashes`: fuzzer/runtime/unclassified artifacts (for example a
  crash inside `fuzzer::Fuzzer::ExecuteCallback` or an unknown timeout). Do not
  report them as project bugs.

## Classes ASan catches

| Class | ASan summary |
| --- | --- |
| Heap out-of-bounds read/write | `heap-buffer-overflow` |
| Stack out-of-bounds | `stack-buffer-overflow` |
| Global out-of-bounds | `global-buffer-overflow` |
| Use-after-free | `heap-use-after-free` |
| Double free | `attempting double-free` / `double-free` |
| NULL / invalid dereference | `SEGV` |
| Use-after-return | needs `detect_stack_use_after_return=1` |
| Memory leak | LSan; usually disabled in fuzzing (`detect_leaks=0`) |
| Integer UB | UBSan (`undefined` sanitizer) |

## Validated bug zoo

`fixtures/c-bug-zoo` has six handlers behind one message dispatcher. A
15-second fork campaign found all six target signatures:

```
heap-buffer-overflow     bug_zoo.c:25 in heap_oob
heap-use-after-free      bug_zoo.c:42 in use_after_free
double-free              bug_zoo.c:56 in double_free
stack-buffer-overflow    bug_zoo.c:66 in stack_oob
SEGV                     bug_zoo.c:76 in null_deref
global-buffer-overflow   bug_zoo.c:85 in global_oob
```

Run statistics: libFuzzer cov=35, ft=307, corpus=163; source coverage 64/86
lines (74.42%), 7/7 functions, 36/44 branches. Each saved input reproduced with
`dtfuzz repro` (SIGABRT / ASan summary with `file:line`). The run also produced
four non-target fuzzer/runtime artifacts; those are listed separately and were
not counted as project bugs.

Demo artifacts (report, findings table, coverage, reproducers):

```
auto-dtfuzz-workspace/iteration-3-bug-zoo/
├── report.md
├── findings.md
├── coverage-summary.json
└── repo/.dtfuzz/bug_dispatch/crashes/<id>/
```

## Caveats

- **Optimization can remove a bug.** A store to a dead static array or a
  malloc/free pair can be optimized away at `-O1`. Real code may be less
  affected, but a fixture needs `volatile`/`noinline` or an observable use to
  keep the bug. If a suspected bug never appears, inspect the assembly or build
  at `-O0` for verification.
- **A sanitizer finding is not automatically a vulnerability.** Check reachability
  from the entry, input constraints, impact (read vs write, attacker control),
  and whether the surrounding system would ever supply that input.
- **Coverage and bugs are different objectives.** A crash-heavy target can show
  lower source coverage because fork children abort before flushing counters.
  Do not classify those lines as unreachable without checking the crash list.
- **Deterministic mocks and crashes.** Mock randomness is seeded per input, so a
  reproducer containing the same input reproduces the same mock behavior.
- **Resource limits.** ASan/UBSan increase memory; keep `rss_limit_mb` and
  `timeout` realistic, especially for large messages.
