#!/usr/bin/env bash
# Run on Linux with a preinstalled Gemini CLI 0.66.0, Node, mise, and libseccomp.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
aerlog=$(realpath "${1:-$repo/.venv/bin/aerlog}")
python=$(command -v python3)
node=$(command -v node)
gemini_install=$(mise where gemini@0.66.0)
core="$gemini_install/node_modules/@google/gemini-cli/bundle/chunk-RZ3ZVTZB.js"
test -x "$aerlog"
test -r "$core"

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch"/{home/.gemini,project/.gemini,config,cache,xdg-data}
"$python" - "$scratch" "$repo" "$aerlog" "$python" <<'PY'
import json
import sys
from pathlib import Path

scratch, repo, aerlog, python = map(Path, sys.argv[1:])
project = scratch / "project"
settings = {"mcpServers": {"aerlog-quickstart": {
    "command": str(aerlog),
    "args": ["run", "--data-dir", str(scratch / "capture"), "--", str(python),
             str(repo / "examples/quickstart_server.py")],
    "timeout": 5000,
}}}
(project / ".gemini/settings.json").write_text(json.dumps(settings), encoding="utf-8")
(scratch / "home/.gemini/trustedFolders.json").write_text(
    json.dumps({str(project): "TRUST_FOLDER"}), encoding="utf-8"
)
PY

isolated() {
    env -i HOME="$scratch/home" GEMINI_CLI_HOME="$scratch/home" \
        XDG_CONFIG_HOME="$scratch/config" XDG_CACHE_HOME="$scratch/cache" \
        XDG_DATA_HOME="$scratch/xdg-data" PATH="$(dirname "$node"):/usr/bin:/bin" \
        MISE_DATA_DIR="$(realpath "$gemini_install/../../..")" GEMINI_CLI_NO_RELAUNCH=1 \
        GEMINI_CLI_SYSTEM_SETTINGS_PATH="$scratch/no-system-settings.json" \
        GEMINI_CLI_SYSTEM_DEFAULTS_PATH="$scratch/no-system-defaults.json" \
        NO_COLOR=1 timeout 20 "$python" "$repo/examples/gemini-smoke/offline.py" "$@"
}

cd "$scratch/project"
status=$(isolated mise x gemini@0.66.0 -- gemini mcp list 2>&1)
printf '%s\n' "$status"
[[ $status == *'Connected'* ]]
isolated "$node" "$repo/examples/gemini-smoke/call.mjs" "$core"

isolated "$python" - "$scratch/capture" "$aerlog" <<'PY'
import subprocess
import sys
from pathlib import Path

data, aerlog = map(Path, sys.argv[1:])
timelines = []
for execution in (data / "executions").iterdir():
    timeline = subprocess.check_output(
        [str(aerlog), "timeline", execution.name, "--data-dir", str(data)], text=True
    )
    timelines.append(timeline)
    print(timeline)
assert len(timelines) == 2, len(timelines)
for timeline in timelines:
    assert "[status=incomplete" in timeline and "proxy signal SIGTERM" in timeline
assert any("response for ping" in timeline for timeline in timelines)
assert any(
    all(marker in timeline for marker in (
        "response for tools/list", "tools/call [tool=echo_message]", "response for tools/call"
    ))
    for timeline in timelines
)
PY
