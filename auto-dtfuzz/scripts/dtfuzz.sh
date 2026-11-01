#!/bin/sh
# Run the dtfuzz CLI without installing the package.
# Usage: /path/to/skill/scripts/dtfuzz.sh <command> [args...]
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m dtfuzz "$@"
