# Background: oss-fuzz-gen design patterns

This note records what dtfuzz borrowed from Google's
[oss-fuzz-gen](https://github.com/google/oss-fuzz-gen), what it deliberately
changed, and the pitfalls the original design exposes for a single-module,
message-entry fuzzing tool. Source facts below were read from the oss-fuzz-gen
repository (main branch); file paths are given for follow-up reading.

## Pipeline

oss-fuzz-gen runs three stages and up to five cycles
(`pipeline.py`, `max_cycle_count = 5`):

1. **Writing** (`stage/writing_stage.py`): chooses a writer from the current
   state — a Prototyper when there is no valid target, a fixer after a build
   failure, an Enhancer once a target builds.
2. **Execution** (`stage/execution_stage.py`): creates a synthetic OSS-Fuzz
   project, swaps in the generated target, runs `Evaluator.check_target` and
   `BuilderRunner`, then builds/runs/collects coverage.
3. **Analysis** (`stage/analysis_stage.py`): crash → CrashAnalyzer (and
   ContextAnalyzer if it is a true bug); otherwise CoverageAnalyzer, with a
   SemanticAnalyzer fallback.

Results flow Build → Run → Analysis → Trial (`results.py`).

## Prompting

`llm_toolkit/prompt_builder.py` (`DefaultTemplateBuilder`) uses:

- a priming prompt (“security engineer writing a {LANGUAGE} fuzzer”, must call
  the target signature inside `LLVMFuzzerTestOneInput`, no NULL arguments,
  deterministic);
- two cross-project examples plus same-project examples from existing
  OSS-Fuzz targets (`use_project_examples`), selected to fit the context
  window;
- a problem statement containing the signature and “You MUST call …”;
- optional Fuzz-Introspector context (`data_prep/project_context/context_introspector.py`):
  headers, declarations, typedefs, function source, callers, tests;
- an agent-mode FunctionAnalyzer that adds setup calls, valid arguments,
  pointer/size relations, and which bytes to fuzz.

`prompts/example/dns_message_parse.c` is the closest published template for a
message-entry parser (init context → parse(input,len) → render → detach).

C/C++ differ: priming files `prompts/agent/prototyper-priming.{c,cpp}.txt`,
`FuzzedDataProvider` for C++ only, `needs_extern` for C++ harnesses in C
projects, and `llm_toolkit/code_fixer.py` post-fixes `extern "C"`,
`<cstdint>`, `<cstdlib>`.

Repair: `code_fixer.py` parses clang diagnostics anchored to the target file
and linker `undefined reference` / `multiple definition` errors, groups
multi-line errors, dedups, and feeds the full code plus `<error>` summary back
to the fixer. `LLM_FIX_LIMIT = 5` (`experiment/evaluator.py`).

## Build

oss-fuzz-gen does **not** integrate CMake or Make. The generated harness lives
inside an OSS-Fuzz project image, and `experiment/builder_runner.py` runs:

```
docker build gcr.io/oss-fuzz/<project>
docker run --platform linux/amd64 --privileged --shm-size=2g \
  -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e ARCHITECTURE=x86_64 \
  -e PROJECT_NAME=<p> -e FUZZING_LANGUAGE=c ... /bin/bash -c compile
```

The container supplies `CC/CXX/CFLAGS/CXXFLAGS` and
`LIB_FUZZING_ENGINE=/usr/lib/libFuzzingEngine.a`. Address flags include
`-fsanitize=address -fsanitize-address-use-after-scope`; coverage flags include
`-fprofile-instr-generate -fcoverage-mapping -pthread ...`; normal builds use
`COVERAGE_FLAGS=-fsanitize=fuzzer-no-link`. The harness replaces the human
target; the original `build.sh` is kept as `/src/build.bk.sh`.

## Coverage

Runs use `infra/helper.py run_fuzzer` with
`-print_final_stats=1 -max_total_time=30 -len_control=0 -timeout=30
-detect_leaks=0`.

Two metrics:

- **PC coverage** = `cov_pcs/total_pcs` from `cov: N ft:` and
  `INFO: Loaded N PC tables (...)`.
- **Line coverage** from a coverage-sanitizer build and the helper’s
  `coverage` command:
  `LLVM_PROFILE_FILE=<dumps>/<t>.%1m.profraw /out/<t> -merge=1 ...`;
  `llvm-profdata merge -j=1 -sparse <t>.*.profraw -o <t>.profdata`;
  `llvm-cov export -summary-only -instr-profile=... -object=/out/<t>
  -path-equivalence=/,$OUT -ignore-filename-regex=...`;
  `llvm-cov show ... -line-coverage-gt=0 --show-branches=count --show-expansions`.

`line_coverage_diff` subtracts the existing human-target text coverage (from a
GCS bucket) from newly covered project lines, divided by total project lines
excluding fuzz-target files (`experiment/evaluator.py`). `textcov.py` keys
lines by function name + stripped line content after `c++filt`; it is fragile.
There is no per-target-function coverage gate. The CoverageAnalyzer receives
the run log, harness, and requirements, uses bash tools to inspect source, and
emits `improve_required`/insights/suggestions. The precise uncovered text
coverage is used for reporting but **never fed to the next prompt**.

## Iteration and crashes

Defaults: 2 samples, temperature 0.4 (`run_one_experiment.py`). Stops after five
cycles, a failed BuildResult, a non-AnalysisResult, or a “successful”
AnalysisResult (`pipeline.py`). Success means no semantic error, the coverage
analyzer says no improvement is needed, or a crash is a true bug / the entry
point is infeasible. There is no numeric coverage threshold. Best trial is
chosen by maximum `line_coverage_diff`, then maximum coverage, then the last
build success (`results.py`).

`agent/semantic_analyzer.py` parses stacks and filters false positives first:
null deref, signal, exit, const overwrite, OOM, crash within the first three
rounds, first project frame is `LLVMFuzzerTestOneInput`, or no coverage
increase. Survivors go to `agent/crash_analyzer.py`, which reruns under GDB and
returns `true_bug` + insight; `context_analyzer.py` checks reachability. Local
runs copy the first `crash-*` reproducer. There is no stack-hash dedup;
downstream ClusterFuzz does real deduplication.

## Pitfalls for one module in an arbitrary repo

- **Hard OSS-Fuzz dependencies.** The image, Fuzz Introspector, and GCS baseline
  are unavailable for a single module. dtfuzz replaces them with local
  clang+libFuzzer, a local baseline, and AST/`compile_commands.json` context.
- **Coverage denominator.** oss-fuzz-gen measures the whole linked project and
  its build script can link extra code (the README warns about inflation).
  dtfuzz measures only configured target files and reads per-file/function
  `llvm-cov export` JSON, so the harness and mocks do not inflate the number.
- **No stubbing or mocking.** oss-fuzz-gen prompts may mention mocking, but
  generated harnesses call real code. A telecom message-entry parser pulls in a
  large dependency graph, causing link failures, heavy initialization, and
  false crashes. dtfuzz is link-first: it finds and links real implementations
  across the repo (excluding `dt/`, tests, mocks, stubs, fakes), probes the link
  closure, and only asks for human mock rules for symbols that remain
  unresolved. Confirmed mock code lives in `fuzz_mocks/<module>/`, not in
  `.dtfuzz`, and pending entries are not generated.
- **Uncovered lines are not fed back.** dtfuzz includes uncovered
  functions/lines, source snippets, and current mock bodies in the optimizer
  prompt, and accepts structured seeds/dict/mock patches back.
- **30-second runs and five cycles are shallow** for parser state machines.
  dtfuzz rounds are configurable and stop on target/plateau/max rounds.
- **No examples/corpus.** oss-fuzz-gen can mine unit tests (it has a
  TestToHarness converter). dtfuzz mines README hex samples, dictionary tokens,
  and type constants; unit-test mining is a future extension.
- **Conservative build edits.** oss-fuzz-gen tries the original build first.
  dtfuzz never edits the target repository; it compiles into
  `<repo>/.dtfuzz/<module>/` and records the exact commands.

## What dtfuzz implements differently

| Concern | oss-fuzz-gen | dtfuzz |
| --- | --- | --- |
| Target context | Docker + Fuzz Introspector | clang JSON AST + compile_commands |
| Dependencies | real code / OSS-Fuzz image | link real implementations first; human-rule mocks only for unlinkable symbols, in `fuzz_mocks/` |
| Coverage | PC + project-wide line diff | per-target line/function/branch JSON |
| Feedback | qualitative log analysis | uncovered JSON + source + mock bodies in prompt |
| Iteration | 5 cycles, no numeric threshold | target/plateau/max-round config |
| Crashes | GDB true-bug pipeline | ASan/UBSan + stack dedup + repro |
| Harness style | project image build.sh | standalone clang build, no repo edits |

## Key citations

- `pipeline.py`; `stage/{writing_stage,execution_stage,analysis_stage}.py`
- `agent/{prototyper,one_prompt_prototyper,enhancer,coverage_analyzer,crash_analyzer,semantic_analyzer,function_analyzer,context_analyzer}.py`
- `llm_toolkit/{prompt_builder,code_fixer}.py`
- `prompts/template_xml/{priming,problem,context,fixer_problem}.txt`
- `prompts/agent/{prototyper-priming.c,prototyper-priming.cpp,coverage-analyzer-priming,enhancer-coverage-priming,function-analyzer-priming}.txt`
- `prompts/example/dns_message_parse.c`
- `experiment/{builder_runner,evaluator,textcov,benchmark,fuzz_target_error}.py`
- `data_prep/project_context/context_introspector.py`
- OSS-Fuzz `infra/base-images/base-builder/{compile,Dockerfile}` and
  `base-runner/{coverage,run_fuzzer}`
