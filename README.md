# auto-dtfuzz

面向 **C/C++ 消息入口函数** 的 libFuzzer 自动化测试 Skill：自动分析入口、生成 harness、优先链接真实实现、按人工规则生成 mock、自动编译运行，并用覆盖率反馈持续优化语料，最终产出覆盖率与崩溃报告。

本仓库同时包含：

- 一个可被 Claude Code 直接加载的 Skill：`auto-dtfuzz/`
- 一个无第三方 Python 依赖的 CLI：`auto-dtfuzz/scripts/dtfuzz.sh`
- CLI/配置/覆盖率/崩溃分析参考文档：`auto-dtfuzz/references/`

> 目标场景：给一个消息分发/解析函数（例如 `msg_dispatch(uint8_t type, const uint8_t *buf, size_t len)`）快速搭建可运行的 libFuzzer 工程，并把“真实链接优先、只对无法链接的函数打桩、人工确认 mock 语义”的流程固化下来。

---

## 目录结构

```text
dtfuzz-skill/
├── README.md
├── .gitignore
└── auto-dtfuzz/                 # Skill 根目录，目录名必须保持此名称
    ├── SKILL.md                      # Claude Code 读取的技能说明与工作流
    ├── scripts/
    │   ├── dtfuzz.sh                 # 免安装 CLI 入口
    │   ├── pyproject.toml            # 可选 pipx/ pip 安装元数据
    │   └── dtfuzz/                   # Python CLI 实现（仅标准库）
    ├── references/
    │   ├── cli.md                    # 命令、config.json、mocks.json 字段
    │   ├── mock-config.md            # mock 规则与示例
    │   ├── coverage-loop.md          # 覆盖率缺口分类与优化策略
    │   ├── bug-finding.md            # fork 模式与 ASan 崩溃挖掘
    │   ├── platforms.md              # macOS / WSL / Linux 工具链
    │   └── oss-fuzz-gen-notes.md     # 设计参考
    └── evals/
        └── evals.json                # 回归测试用例定义
```

运行产物不会写进本仓库：测试工作区在目标仓库的 `<repo>/.dtfuzz/<module>/`，人工可维护的 mock 在 `<repo>/fuzz_mocks/<module>/`。

---

## 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | macOS、Linux，或 Windows + WSL。**不支持原生 Windows 直接编译 fuzz 目标** |
| Python | 3.10+，只用标准库，无需 `pip install` |
| 编译器 | 带 libFuzzer runtime 的 clang（推荐 Homebrew LLVM / 系统 LLVM） |
| 覆盖率工具 | 与 clang 同一 LLVM 版本的 `llvm-cov`、`llvm-profdata`、`llvm-symbolizer`、`llvm-cxxfilt` |
| 其他 | `make` 可选；`cmake`/`ninja` 可选，dtfuzz 直接调用 clang 编译 |
| Claude Code | 仅在导入 Skill 时需要；CLI 可以独立使用 |

> Apple Command Line Tools 自带的 clang 通常**没有** libFuzzer runtime，macOS 上请使用 Homebrew LLVM。
>
> WSL/Linux 上建议把代码放在 Linux 文件系统（如 `~/src/project`），不要放在 `/mnt/c/...`，否则编译和 fuzz 吞吐会明显变慢。

---

## 安装

### 1. 安装工具链

**macOS**

```sh
brew install llvm
```

`dtfuzz doctor` 会自动优先选择 `/opt/homebrew/opt/llvm/bin/clang` 或 `/usr/local/opt/llvm/bin/clang`。如果自动探测不符合预期，可显式指定：

```sh
export DTFUZZ_CLANG=/opt/homebrew/opt/llvm/bin/clang
```

**Ubuntu / Debian / WSL**

```sh
sudo apt update
sudo apt install clang libclang-rt-dev llvm make
```

**Fedora**

```sh
sudo dnf install clang compiler-rt llvm make
```

安装后检查 clang 是否带 fuzzer runtime：

```sh
clang --version
clang -print-resource-dir
ls "$(clang -print-resource-dir)"/lib/*/libclang_rt.fuzzer*
llvm-cov --version
llvm-profdata --version
```

> `clang`、`llvm-cov`、`llvm-profdata` 必须来自同一个 LLVM release。

### 2. 获取本仓库

```sh
git clone <本仓库地址> ~/src/dtfuzz-skill
cd ~/src/dtfuzz-skill
```

如果已经下载/解压，确认 `auto-dtfuzz/SKILL.md` 存在即可。

### 3. 导入 Claude Code

Claude Code 从 `SKILL.md` 所在目录发现 skill。目录名需要保持 `auto-dtfuzz`，并与 `SKILL.md` frontmatter 中的 `name` 一致。

#### 方式 A：用户级 Skill（推荐，所有项目可用）

**符号链接安装**（`git pull` 后自动生效）：

```sh
mkdir -p ~/.claude/skills
ln -s ~/src/dtfuzz-skill/auto-dtfuzz ~/.claude/skills/auto-dtfuzz
```

如果 `~/.claude/skills/auto-dtfuzz` 已存在，先确认旧版本是否需要备份，再替换。

**复制安装**（不依赖符号链接）：

```sh
mkdir -p ~/.claude/skills
cp -R ~/src/dtfuzz-skill/auto-dtfuzz ~/.claude/skills/
chmod +x ~/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh
```

> Windows 原生环境：Claude Code 的用户级 skill 目录是 `%USERPROFILE%\.claude\skills\`，但 dtfuzz 的编译和 fuzz 必须在 WSL 内执行。推荐直接在 WSL 中运行 Claude Code，并使用 WSL 的 `~/.claude/skills`。

#### 方式 B：项目级 Skill（只对某个仓库生效）

把 skill 放入目标项目的 `.claude/skills/`：

```sh
mkdir -p /path/to/your-project/.claude/skills
cp -R ~/src/dtfuzz-skill/auto-dtfuzz /path/to/your-project/.claude/skills/
chmod +x /path/to/your-project/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh
```

项目级 skill 可以随项目提交到 Git，适合团队统一测试流程。

#### 方式 C：只在命令行使用（不导入 Claude Code）

```sh
DTFUZZ="$HOME/src/dtfuzz-skill/auto-dtfuzz/scripts/dtfuzz.sh"
"$DTFUZZ" doctor --json
```

也可以选择通过 pipx 安装 CLI：

```sh
pipx install ~/src/dtfuzz-skill/auto-dtfuzz/scripts
dtfuzz doctor --json
```

### 4. 验证安装

先验证 CLI：

```sh
~/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh doctor --json
```

期望输出包含：

```json
{
  "ok": true,
  "fuzz_ok": true,
  "coverage_ok": true
}
```

- `fuzz_ok: true`：clang 和 libFuzzer runtime 可用，能编译、运行、发现崩溃。
- `coverage_ok: true`：`llvm-cov` / `llvm-profdata` 可用，能输出源码覆盖率和执行 `optimize`。
- 只有 `fuzz_ok` 时仍可使用 libFuzzer 自身的 `cov` / `ft` / `corp` 反馈，但没有源码覆盖率表和 `optimize`。

然后重启 Claude Code（或新开一个会话），在可用 skills 列表中确认能看到 `auto-dtfuzz`。也可以直接用斜杠命令调用：

```text
/auto-dtfuzz
```

如果看不到，检查：

```sh
ls -la ~/.claude/skills/auto-dtfuzz
test -f ~/.claude/skills/auto-dtfuzz/SKILL.md && echo OK
```

---

## 在 Claude Code 中使用

导入后，不需要手动记命令，直接用自然语言描述目标即可。建议一次说清楚：

1. 仓库路径
2. 入口函数名与源码文件
3. 消息格式（类型字段宽度/字节序、缓冲区、长度参数）
4. 哪些目录是 `dt/`、mock、stub、fake，绝对不能链接
5. 无法链接的函数及其 mock 规则
6. 单轮 fuzz 时长、覆盖率目标或是否以找崩溃为目标

### 示例提示词：覆盖率优先

```text
用 dtfuzz 对 /path/to/repo 的 msg_dispatch 做 libFuzzer 测试。
入口源码是 src/msg_parser.c，签名：
int msg_dispatch(uint8_t type, const uint8_t *buf, size_t len);
输入第 1 字节是消息类型，后面是 payload。

先全仓扫描并链接可用的真实实现；有实现的函数不要 mock。
仓库里的 dt/ 是旧测试假实现，绝对不能链接，也不能复制其中的逻辑。
只有确实无法链接的函数才 mock，规则先列给我确认，不要自动打桩。
单轮 60 秒，目标行覆盖率 90%，最后给我覆盖率、未覆盖原因和产物路径。
```

### 示例提示词：崩溃挖掘

```text
用 dtfuzz 对 /path/to/repo 的 crash_dispatch 做 ASan 崩溃挖掘。
入口是 src/crash_parser.c，消息格式为：1 字节类型 + payload。
用 fork 模式跑 120 秒，收集所有可区分的 sanitizer 签名和可复现输入；
区分目标代码崩溃与非目标/运行时崩溃，最后给出复现命令和栈顶。
```

Claude Code 会按 `SKILL.md` 的流程执行：

```text
doctor -> init/analyze -> probe -> 人工确认 mock -> gen -> build
        -> round -> coverage -> optimize/import -> round -> report
```

---

## CLI 快速开始

以下命令可以直接复制修改。示例入口为 `msg_dispatch`：

```sh
DTFUZZ="$HOME/src/dtfuzz-skill/auto-dtfuzz/scripts/dtfuzz.sh"
REPO=/abs/path/to/your-project
WORK="$REPO/.dtfuzz/msg_dispatch"

# 0. 工具链检查
"$DTFUZZ" doctor --json

# 1. 分析入口、全仓找定义、探测链接缺口
"$DTFUZZ" init \
  --repo "$REPO" \
  --entry msg_dispatch \
  --source src/msg_parser.c \
  --workdir "$WORK" \
  --json

# 2. 查看待确认的 mock 符号
"$DTFUZZ" mocks list --workdir "$WORK" --json

# 3. 人工给出规则后导入（见下一节）
"$DTFUZZ" mocks import --workdir "$WORK" --file /tmp/mock_rules.json --json

# 4. 生成 harness、字典、种子和 mock 代码
"$DTFUZZ" gen --workdir "$WORK" --json

# 5. 编译
"$DTFUZZ" build --workdir "$WORK" --json

# 6. 跑一轮并收集覆盖率
"$DTFUZZ" round --workdir "$WORK" --seconds 60 --json

# 7. 让 CLI 生成覆盖率优化提示词
"$DTFUZZ" optimize --workdir "$WORK" --mode prompt --json

# 8. 根据提示词生成 seeds/dict 后导入；如果改了 mock，会自动 gen/build
"$DTFUZZ" optimize --workdir "$WORK" --mode import --file /tmp/opt_result.json --json

# 9. 再跑一轮
"$DTFUZZ" round --workdir "$WORK" --seconds 60 --json

# 10. 生成最终报告
"$DTFUZZ" report --workdir "$WORK" --json
```

### 崩溃挖掘

```sh
# fork 模式：子进程崩溃不会终止整个 campaign
"$DTFUZZ" round --workdir "$WORK" --seconds 120 --fork --json

# 复现某个目标崩溃
"$DTFUZZ" repro --workdir "$WORK" --input "$WORK/crashes/<id>/input" --json
```

`round` 的 JSON 中：

- `run.crashes`：目标代码的 sanitizer 崩溃，按“sanitizer 摘要 + 栈顶帧”去重。
- `run.non_target_crashes`：fuzzer/运行时/未分类 artifact，不要当成项目漏洞。
- `run.stats`：libFuzzer 自身的 `cov`、`ft`、`corp` 反馈。

---

## Mock 规则

Mock 文件位置：

```text
<repo>/fuzz_mocks/<module>/
├── mocks.json              # 人工规则：confirmed 的符号才会生成代码
├── generated_mocks.c|cc    # 由 CLI 生成，不要手改
├── custom_mocks.c|cc       # 可选手写实现，与生成文件一起编译
└── dtfuzz_runtime.h        # 输入/随机数辅助函数
```

`mocks.json` 示例：

```json
{
  "symbols": {
    "proto_crc32": {
      "confirmed": true,
      "return": {
        "mode": "random_choice",
        "values": ["0", "-1", "-123"]
      }
    },
    "cfg_get_u16": {
      "confirmed": true,
      "return": {
        "mode": "random_error",
        "success": "0",
        "errors": ["-1"]
      },
      "out_params": {
        "out": {
          "mode": "random_bytes",
          "length": 2
        }
      }
    },
    "peer_lookup": {
      "confirmed": true,
      "return": {
        "mode": "random_choice",
        "values": ["0", "-1"]
      },
      "out_params": {
        "out": {
          "mode": "set_field",
          "field": "code",
          "value": "0x99"
        }
      }
    }
  }
}
```

常用规则：

| 类型 | 写法 |
| --- | --- |
| 固定返回 | `{"mode":"fixed","value":"0"}` |
| 随机选一个返回 | `{"mode":"random_choice","values":["0","-1","-2"]}` |
| 成功/随机错误码 | `{"mode":"random_error","success":"0","errors":["-1","-2"]}` |
| 按调用次数返回 | `"return_sequence": ["0","-1","0"]` |
| out 清零 | `{"mode":"zero","size":"sizeof(*out)"}` |
| out 填固定值 | `{"mode":"set","value":"-1"}` |
| out 填结构字段 | `{"mode":"set_field","field":"code","value":"0x99"}` |
| out 随机定长字节 | `{"mode":"random_bytes","length":16}` |
| out 随机定长 hex 字符串 | `{"mode":"random_hex_string","length":32,"terminate":true}` |
| 完全自定义 | `"body": "完整的 C/C++ 语句"` |

注意事项：

- 只有 `confirmed: true` 的规则才会生成代码；未确认的符号会保持 pending，构建时报未定义。
- 随机规则使用“由 fuzz 输入派生的确定性 RNG”，同一个输入行为可复现，不同输入可探索成功/失败分支。
- `body` 中可使用 `dtfuzz_input_byte(i)`、`dtfuzz_input_size()`、`dtfuzz_rand()`、`dtfuzz_random_bytes(p, n)`、`dtfuzz_random_hex(p, n, terminate)`。
- 不要手工编辑 `generated_mocks.*`；改 `mocks.json` 后重新执行 `gen` / `build`。
- 不要使用 `--auto-stub` 绕过人工规则，除非只是临时验证构建链路。

---

## 覆盖率与产物

工作区结构：

```text
<repo>/.dtfuzz/<module>/
├── config.json
├── analysis.json
├── harness/fuzz_target.c|cc
├── harness/dict.txt
├── corpus/
├── build/fuzz_target
├── build/build.json
├── build/build.log
├── coverage/summary.json
├── coverage/history.json
├── runs/history.json
├── crashes/<id>/
├── artifacts/
└── report.md
```

关键文件：

- `coverage/summary.json`：行/函数/分支覆盖率、未覆盖行、部分覆盖函数、libFuzzer 反馈。
- `report.md`：最终 Markdown 报告。
- `build/build.log`：编译/链接失败时的第一手错误。
- `runs/history.json`：每轮 stats、崩溃列表。
- `crashes/<id>/input`：可复现输入。

查看覆盖率时请以 `coverage/summary.json` 或 `round` 返回的 `coverage` 对象为准，不要只凭 libFuzzer 的 `cov` 数字推断源码行覆盖率。

---

## 大项目 / 预构建库

对于 OpenSSL 这类已经构建好 `libcrypto.a`、不方便按源码闭包全量重编的项目：

```sh
"$DTFUZZ" init --repo "$REPO" --entry ASN1_parse --source crypto/asn1/asn1_parse.c \
  --workdir "$WORK" --no-real-scan --json
```

然后只把需要 ASan 插桩的目标文件放入 `sources.target`，把预构建库放入 `sources.libraries`：

```sh
"$DTFUZZ" config set --workdir "$WORK" --patch-json '{
  "sources": {
    "target": [
      "crypto/asn1/asn1_parse.c",
      "crypto/asn1/asn1_lib.c"
    ],
    "real": [],
    "libraries": ["/abs/path/to/libcrypto.a"],
    "include_dirs": ["/abs/path/to/repo", "/abs/path/to/repo/include"],
    "defines": ["L_ENDIAN", "OPENSSL_PIC", "_REENTRANT"],
    "std": "gnu11"
  },
  "coverage": {
    "target_files": ["/abs/path/to/repo/crypto/asn1/asn1_parse.c"]
  },
  "harness": {
    "extra_includes": [
      "#include <openssl/asn1.h>",
      "#include <openssl/bio.h>"
    ],
    "call_expr": "do { BIO *bp = BIO_new(BIO_s_mem()); if (bp != NULL) { (void)ASN1_parse(bp, {data}, (long){size}, 0); BIO_free(bp); } } while (0)"
  }
}' --json

# 如果库已经解析了所有符号，清空 pending mock
"$DTFUZZ" mocks clear --workdir "$WORK" --json
"$DTFUZZ" gen --workdir "$WORK" --json
"$DTFUZZ" build --workdir "$WORK" --json
```

注意：

- 只有重新编译的 `sources.target` 文件带 ASan/覆盖率插桩；预构建库里的对象保持原构建参数，**其中的内存错误不会被 ASan 捕获**。
- 覆盖率目标应只设为实际插桩的文件，否则会被未插桩的库文件拉低。
- 如需全库 ASan，必须用 `-fsanitize=address` 重新构建依赖库。

---

## 重要约束

- **真实链接优先**：全仓扫描定义（允许跨模块），有真实实现就链接，不要 mock。
- **默认排除假实现目录**：`dt`、`tests`、`test`、`mock`、`mocks`、`stub`、`stubs`、`fake`、`fakes`、`fuzz_mocks`。不要链接，也不要复制其中的函数体。
- **Mock 语义由人确认**：不要自行编造返回值/out 参数行为；未确认的 mock 不生成。
- **不要修改目标仓库源码**：工作区在 `.dtfuzz`，mock 在 `fuzz_mocks`，只报告发现，不改业务代码。
- **只在有授权的目标上 fuzz**：保持 libFuzzer 资源限制，不要对网络服务或破坏性目标运行。
- **不要手改生成文件**：改 `config.json` 或 `mocks.json`，再 `gen`/`build`。

---

## 常见问题

### `doctor` 显示 `fuzz_ok: false`

macOS 上通常是用了 Apple CLT 的 clang：

```sh
brew install llvm
~/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh doctor --json
```

仍不行时显式指定：

```sh
export DTFUZZ_CLANG=/opt/homebrew/opt/llvm/bin/clang
```

Linux/WSL 检查是否安装了 `compiler-rt` / `libclang-rt-dev`，并确认 `libclang_rt.fuzzer*` 存在：

```sh
ls "$(clang -print-resource-dir)"/lib/*/libclang_rt.fuzzer*
```

### `coverage_ok: false`

安装同版本的 LLVM 工具，或把 `llvm-cov`、`llvm-profdata` 所在目录放到 `PATH` 前面。不要混用不同 LLVM release。

### Claude Code 看不到 skill

- 确认路径是 `~/.claude/skills/auto-dtfuzz/SKILL.md`（目录名不能改）。
- 不要出现多一层嵌套，例如 `~/.claude/skills/auto-dtfuzz/auto-dtfuzz/SKILL.md`。
- 重启 Claude Code 或新开会话。
- 直接输入 `/auto-dtfuzz`（若当前版本支持斜杠调用）；仍不触发时用自然语言描述“用 dtfuzz 对某个函数做 libFuzzer 测试”。
- 项目级安装时确认是 `<project>/.claude/skills/auto-dtfuzz/`。

### `build` 链接失败，提示未定义符号

先看 `build/build.json` 的 `undefined_symbols` 和 `pending_mocks`，再看 `build/build.log`。通常是有符号还没有人工 mock：

```sh
"$DTFUZZ" mocks list --workdir "$WORK" --json
# 按人工规则写 /tmp/mock_rules.json
"$DTFUZZ" mocks import --workdir "$WORK" --file /tmp/mock_rules.json --json
"$DTFUZZ" gen --workdir "$WORK" --json
"$DTFUZZ" build --workdir "$WORK" --json
```

不要通过添加 `dt/` 或 `mock/` 源文件来“修复”链接。

### `round` 的覆盖率是 `null`

目标在写出 `.profraw` 之前崩溃了。先看 `run.crashes`，再用 fork 模式继续跑：

```sh
"$DTFUZZ" round --workdir "$WORK" --seconds 120 --fork --json
```

### WSL 下编译/fuzz 很慢

把仓库放到 WSL 的 Linux 文件系统（例如 `~/src/project`），不要放在 `/mnt/c/...`。

### 原生 Windows 可以吗？

不推荐。Windows 原生环境缺少本 skill 依赖的 Linux/macOS 工具链行为，请使用 WSL；libFuzzer 目标也应在 WSL 内编译和运行。

---

## 更新与卸载

**符号链接安装更新：**

```sh
cd ~/src/dtfuzz-skill
git pull
# 符号链接无需重新安装
```

**复制安装更新：**

```sh
rm -rf ~/.claude/skills/auto-dtfuzz
cp -R ~/src/dtfuzz-skill/auto-dtfuzz ~/.claude/skills/
chmod +x ~/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh
```

**卸载：**

```sh
rm ~/.claude/skills/auto-dtfuzz
# 如果是复制安装而非符号链接：
# rm -rf ~/.claude/skills/auto-dtfuzz
```

---

## 维护者：首次推送到 Git

```sh
cd /path/to/dtfuzz-skill

git init
git add .
git commit -m "feat: add auto-dtfuzz skill and installation guide"
git branch -M main
git remote add origin <你的仓库地址>
git push -u origin main
```

推送前建议确认：

```sh
git status
git ls-files | head
```

仓库中不应包含 `__pycache__/`、`*.pyc`、`.DS_Store`、`.dtfuzz/`、测试语料或崩溃输入；这些已在 `.gitignore` 中忽略。

如果准备公开发布，建议补充 `LICENSE`（当前仓库未声明许可证）。

---

## 版本

当前 CLI 版本：`0.1.0`（见 `auto-dtfuzz/scripts/dtfuzz/__init__.py` 和 `scripts/pyproject.toml`）。

更详细的命令、字段和扩展点见 `auto-dtfuzz/references/`。
