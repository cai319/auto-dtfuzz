# Windows + WSL2 安装指南

`auto-dtfuzz` 必须在 Linux 文件系统内运行；原生 Windows 不支持。推荐：
**WSL2 Ubuntu + Claude Code 安装在 WSL 内**。这样 clang/LLVM/Fuzz
Introspector 都是 WSL 原生路径，避免 `/mnt/c` 的权限和 I/O 问题。

`dtfuzz setup` 默认只打印安装计划，不会修改系统：

```sh
dtfuzz setup --json                 # 平台 + 缺失工具 + 命令计划
dtfuzz setup --components base     # 只看基础工具链
```

真正执行需要显式确认：

```sh
dtfuzz setup --install --yes --components base,fi-light
```

如果 `sudo` 需要密码，命令会拒绝执行并打印手动命令；先 `sudo -v` 再重试。

---

## 1. Windows 侧：安装/确认 WSL2

在 **PowerShell（管理员）**：

```powershell
wsl --install -d Ubuntu-22.04
# 或 Ubuntu-24.04
wsl --set-default-version 2
wsl --update
wsl -l -v
```

`wsl -l -v` 的 `VERSION` 必须是 `2`。安装完成后重启，首次进入 Ubuntu 时创建
Linux 用户名/密码。

可选：在 `C:\Users\<你>\.wslconfig` 限制资源（避免 fuzz 吃满内存）：

```ini
[wsl2]
memory=8GB
processors=4
swap=2GB
```

修改后 `wsl --shutdown` 再重进。

## 2. Ubuntu 侧：基础工具链

进入 WSL：

```powershell
wsl -d Ubuntu-22.04
```

然后：

```sh
sudo apt-get update
sudo apt-get install -y \
  clang llvm lld binutils git python3 python3-venv python3-pip build-essential
```

有些 Ubuntu 版本的 libFuzzer 运行时在独立的 `libclang-rt-<major>-dev` 包里：

```sh
sudo apt-get install -y libclang-rt-dev \
  || sudo apt-get install -y libclang-rt-$(clang -dumpversion | cut -d. -f1)-dev
```

验证：

```sh
clang --version
llvm-cov --version
llvm-profdata --version
find "$(clang -print-resource-dir)" -name 'libclang_rt.fuzzer*'
```

最后一条必须能找到一个 `libclang_rt.fuzzer*.a`。没有的话：

```sh
sudo apt-get install -y libclang-rt-$(clang -dumpversion | cut -d. -f1)-dev
# 或者安装更新版 clang/LLVM（apt.llvm.org / Homebrew 不适用于 WSL）
```

## 3. 安装 auto-dtfuzz

```sh
mkdir -p ~/src ~/.claude/skills
cd ~/src
git clone https://github.com/cai319/auto-dtfuzz.git

cp -R ~/src/auto-dtfuzz/auto-dtfuzz ~/.claude/skills/auto-dtfuzz
chmod +x ~/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh

~/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh doctor --json
```

期望：`ok: true`、`fuzz_ok: true`、`coverage_ok: true`。

可选，把 CLI 放到 PATH：

```sh
mkdir -p ~/.local/bin
ln -sf ~/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh ~/.local/bin/dtfuzz
export PATH="$HOME/.local/bin:$PATH"   # 写入 ~/.bashrc
```

## 4. Claude Code 放在 WSL 内

推荐在 **WSL 的 Ubuntu 终端**里安装并运行 Claude Code，而不是只在 Windows
侧运行。skill 里的 `clang`、`llvm-cov`、`~/src` 路径都按 Linux 解析。

安装方式以 Anthropic 官方 Linux 安装说明为准（例如 npm）：

```sh
node --version   # 没有 Node 就先安装
npm install -g @anthropic-ai/claude-code
claude --version
```

如果只能在 Windows 侧运行 Claude Code，所有 CLI 命令都要显式走 WSL，并引用
WSL 路径，例如：

```powershell
wsl -d Ubuntu-22.04 -- bash -lc '~/.claude/skills/auto-dtfuzz/scripts/dtfuzz.sh doctor --json'
```

不要把 Windows 路径 `C:\...` 直接传给 `--repo`；使用 `/home/<user>/...` 或
`/mnt/c/...`。

## 5. 仓库和外部源码放哪

- 被测仓库、构建产物、语料：放在 **WSL 文件系统**，例如 `~/src/my-repo`。
- 避免在 `/mnt/c/...` 下构建/fuzz：跨文件系统 I/O 很慢，权限/inotify 也可能
  出问题。`dtfuzz setup --repo /mnt/c/...` 会给出 warning。
- Windows 资源管理器访问 WSL 文件：`\\wsl$\Ubuntu-22.04\home\<user>\src`。
- 外部组件源码在 Windows 盘上时：
  - 只做只读扫描：可以直接 `externals add --path /mnt/c/...`；
  - 需要 `--link` 编译：先复制到 WSL 文件系统，再注册。

## 6. Fuzz Introspector（按需）

### 方式 A：已有报告（零安装，推荐）

```sh
dtfuzz init --repo ~/src/my-repo --entry msg_dispatch \
  --source src/msg_parser.c --workdir ~/src/my-repo/.dtfuzz/msg \
  --introspector /path/fuzzerLogFile-msg.data.yaml --json
```

### 方式 B：light 前端（WSL2 推荐）

```sh
dtfuzz setup --install --yes --components fi-light
# 等价于：
# git clone --depth 1 https://github.com/ossf/fuzz-introspector ~/.local/share/fuzz-introspector
# python3 -m venv ~/.local/share/fuzz-introspector/.venv
# ~/.local/share/fuzz-introspector/.venv/bin/pip install -r ~/.local/share/fuzz-introspector/requirements.txt
```

使用：

```sh
dtfuzz introspect --workdir ~/src/my-repo/.dtfuzz/msg --run-light \
  --fi-src ~/.local/share/fuzz-introspector \
  --fi-python ~/.local/share/fuzz-introspector/.venv/bin/python --json
```

light 模式不需要自定义 clang；但 `linkageType` 为空，defined/undefined 由 link
probe 决定。

### 方式 C：LTO pass（可选，重）

需要带 Fuzz Introspector LLVM pass 的自定义 clang（Linux + gold），构建时间很长：

```sh
dtfuzz setup --components fi-lto
# 或手动：
git clone --depth 1 https://github.com/ossf/fuzz-introspector ~/.local/share/fuzz-introspector
sudo apt-get install -y binutils texinfo cmake ninja-build
cd ~/.local/share/fuzz-introspector && ./build_all.sh
```

然后：

```sh
dtfuzz introspect --workdir ~/src/my-repo/.dtfuzz/msg --run-lto \
  --fi-clang ~/.local/share/fuzz-introspector/build/llvm-build/bin/clang \
  --fi-src ~/.local/share/fuzz-introspector --json
```

除非确实需要 `linkageType`，优先用 A/B。

### 方式 D：OSS-Fuzz Docker

Docker Desktop for Windows 打开 "Use the WSL 2 based engine" 和对应发行版的
integration；或 `sudo apt-get install docker.io`。然后：

```sh
git clone --depth 1 https://github.com/google/oss-fuzz
cd oss-fuzz
python3 infra/helper.py introspector PROJECT_NAME
```

生成的 `fuzzerLogFile-*.data.yaml` 用 `--introspector` 传给 `dtfuzz init`。

## 7. 用 `dtfuzz setup` 统一检查/安装

```sh
# 1) 看计划（不执行）
dtfuzz setup --json --components base,fi-light

# 2) 允许无密码 sudo 时执行
sudo -v
dtfuzz setup --install --yes --components base,fi-light

# 3) 需要密码时，按打印的命令手动执行
```

`setup` 的安全边界：

- 默认只打印计划；
- `--install` 必须搭配 `--yes`；
- `sudo` 只在 `sudo -n true` 成功时执行，否则只打印；
- 不会静默下载或执行未列出的命令；
- `fi-lto`/`docker` 是显式可选组件。

## 8. 验证清单

```sh
dtfuzz doctor --json
# ok / fuzz_ok / coverage_ok 均为 true

dtfuzz setup --json
# missing 应为空；WSL2 下 notes 会提示路径和 sudo

clang --version
llvm-cov --version
find "$(clang -print-resource-dir)" -name 'libclang_rt.fuzzer*'
```

最小冒烟（用测试 fixture 或你的仓库）：

```sh
dtfuzz init --repo ~/src/my-repo --entry msg_dispatch --source src/msg_parser.c \
  --workdir ~/src/my-repo/.dtfuzz/msg --json
dtfuzz gen --workdir ~/src/my-repo/.dtfuzz/msg --json
dtfuzz build --workdir ~/src/my-repo/.dtfuzz/msg --json
dtfuzz round --workdir ~/src/my-repo/.dtfuzz/msg --seconds 15 --json
```

## 9. 常见问题

| 现象 | 处理 |
| --- | --- |
| `fuzz_ok: false` / 找不到 `libclang_rt.fuzzer` | 安装 `libclang-rt-<major>-dev`；检查 `clang -print-resource-dir` |
| `coverage_ok: false` | 安装 `llvm`；`llvm-cov`/`llvm-profdata` 与 clang 同版本 |
| `sudo: a password is required` | 先 `sudo -v`，或按 `setup` 打印的命令手动运行 |
| `clang: unsupported option '-fsanitize=fuzzer'` | clang 太旧；安装新版 LLVM/clang |
| `/mnt/c` 下编译极慢/权限错误 | 把仓库复制到 `~/src`；外部源码只读扫描可留 `/mnt/c` |
| `fuzz-introspector` 安装 tree-sitter 失败 | `sudo apt install build-essential python3-dev`；用 venv 重试 |
| LTO 报 `cannot find -lLLVM...`/gold 缺失 | `sudo apt install binutils`；`-fuse-ld=gold`；或改用 `--report`/`--run-light` |
| Docker 未运行 | Windows Docker Desktop → Settings → Resources → WSL Integration |
| Claude Code 看不到 skill | 确认 `~/.claude/skills/auto-dtfuzz/SKILL.md`；在 WSL 内重启 Claude Code |
