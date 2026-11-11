"""Packaging, release metadata, README integrity, and quickstart E2E tests."""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

from typer.testing import CliRunner

import aerlog
from aerlog.cli.app import app
from aerlog.events import new_execution_id
from tests.conftest import IsolatedXdgPaths

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_VERSION = "0.1.0"


def _clean_xdg_env(isolated_xdg: IsolatedXdgPaths) -> dict[str, str]:
    env = os.environ.copy()
    env["HOME"] = str(isolated_xdg.home)
    env["XDG_CONFIG_HOME"] = str(isolated_xdg.config_home)
    env["XDG_DATA_HOME"] = str(isolated_xdg.data_home)
    env.pop("AERLOG_CONFIG", None)
    return env


def _run_aerlog_subprocess(
    *args: str,
    env: dict[str, str],
    stdin_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aerlog", *args],
        cwd=_REPO_ROOT,
        env=env,
        input=stdin_text,
        capture_output=True,
        text=True,
        check=False,
    )


def test_version_consistency_and_cli_version() -> None:
    """pyproject.toml, aerlog.__version__, and `aerlog --version` stay in lockstep."""
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    assert project["version"] == _EXPECTED_VERSION
    assert aerlog.__version__ == _EXPECTED_VERSION
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]

    cli_res = CliRunner().invoke(app, ["--version"])
    assert cli_res.exit_code == 0, cli_res.output
    assert cli_res.output.strip() == f"aerlog {_EXPECTED_VERSION}"


def test_sdist_and_wheel_allowlist_prevent_local_leaks(tmp_path: Path) -> None:
    """Built sdist and wheel strictly match the release allowlist without leaking local files."""
    uv_bin = shutil.which("uv")
    assert uv_bin is not None, "uv executable is required to verify distribution archives"

    out_dir = tmp_path / "dist"
    proc = subprocess.run(
        [uv_bin, "build", "--sdist", "--wheel", "--out-dir", str(out_dir)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    sdists = list(out_dir.glob(f"aerlog-{_EXPECTED_VERSION}.tar.gz"))
    wheels = list(out_dir.glob(f"aerlog-{_EXPECTED_VERSION}-*.whl"))
    assert len(sdists) == 1
    assert len(wheels) == 1

    with tarfile.open(sdists[0], "r:gz") as tar:
        members = [m.name for m in tar.getmembers()]
    prefix = f"aerlog-{_EXPECTED_VERSION}/"
    rel_paths = [name[len(prefix) :] if name.startswith(prefix) else name for name in members]
    rel_set = set(rel_paths)

    # Required files/trees must be PRESENT in the source distribution.
    for required_exact in (
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "examples/quickstart_server.py",
        "src/aerlog/__init__.py",
        "src/aerlog/cli/app.py",
        "tests/unit/test_packaging_and_docs.py",
    ):
        assert required_exact in rel_set, f"Missing expected sdist file: {required_exact}"
    assert any(p.startswith("src/aerlog/") for p in rel_paths)
    assert any(p.startswith("tests/") for p in rel_paths)

    # Local-only markdown/prompt/spike/runtime artifacts and bytecode must be ABSENT.
    forbidden_substrings = (
        "RULES.md",
        "RULE.md",
        "AGENT_INSTRUCTIONS.md",
        "EXECUTION_GUIDE.md",
        "MASTER_DEVELOPMENT_STRATEGY.md",
        "prompts/",
        "examples/protocol-spike/",
        ".aerlog/",
        "__pycache__/",
    )
    for rel in rel_paths:
        assert not rel.endswith((".pyc", ".pyo", ".pyd")), f"Bytecode leaked into sdist: {rel}"
        for bad in forbidden_substrings:
            assert bad not in rel, f"Protected or local path {bad!r} leaked into sdist: {rel}"

    with zipfile.ZipFile(wheels[0]) as zf:
        whl_names = zf.namelist()
        meta_matches = [n for n in whl_names if n.endswith("METADATA")]
        assert len(meta_matches) == 1
        meta_text = zf.read(meta_matches[0]).decode("utf-8")

    assert f"Version: {_EXPECTED_VERSION}" in meta_text
    assert "aerlog/__init__.py" in whl_names
    assert "aerlog/cli/app.py" in whl_names
    for whl_entry in whl_names:
        assert not whl_entry.endswith((".pyc", ".pyo", ".pyd")), (
            f"Bytecode leaked into wheel: {whl_entry}"
        )
        for bad in forbidden_substrings:
            assert bad not in whl_entry, f"Forbidden path {bad!r} leaked into wheel: {whl_entry}"


def test_readme_toc_anchors_and_doc_invariants() -> None:
    """Every README TOC link and local file reference resolves cleanly without stale tense."""
    readme_text = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    lines = readme_text.splitlines()

    headings: set[str] = set()
    seen_slugs: dict[str, int] = {}
    in_fence = False
    toc_lines: list[str] = []
    non_fence_lines: list[str] = []
    in_toc = False

    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        non_fence_lines.append(line)
        if line.strip() == "## Table of Contents":
            in_toc = True
            continue
        if in_toc and line.strip() == "---":
            in_toc = False
        if in_toc:
            toc_lines.append(line)
        if line.startswith("#"):
            title = re.sub(r"^#+\s*", "", line).strip()
            # GitHub Markdown anchor conversion preserves internal double hyphens.
            slug = re.sub(r"[^\w\s-]", "", title.lower()).replace(" ", "-")
            idx = seen_slugs.get(slug, 0)
            seen_slugs[slug] = idx + 1
            headings.add(slug if idx == 0 else f"{slug}-{idx}")

    toc_targets = re.findall(r"\(#([^)]+)\)", "\n".join(toc_lines))
    assert toc_targets, "Expected README Table of Contents links"
    missing_anchors = [t for t in toc_targets if t not in headings]
    assert not missing_anchors, f"Broken README TOC anchors: {missing_anchors}"

    # Every relative Markdown file link outside code fences must exist in the repository.
    for link_target in re.findall(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]*)?\)", "\n".join(non_fence_lines)):
        if link_target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (_REPO_ROOT / link_target).exists(), f"Broken README file link: {link_target}"

    assert not re.search(r"\b(proposed|intended)\b", readme_text, re.IGNORECASE)
    assert "not intended to be" not in readme_text.lower()
    assert "--strict-hash-only" not in readme_text
    assert "examples/demo_mcp_server.py" not in readme_text


def test_quickstart_server_stdlib_only_and_end_to_end_cli_workflow(
    isolated_xdg: IsolatedXdgPaths,
    tmp_path: Path,
) -> None:
    """examples/quickstart_server.py uses only stdlib and completes the full CLI lifecycle."""
    script_path = _REPO_ROOT / "examples" / "quickstart_server.py"
    assert script_path.exists()
    source = script_path.read_text(encoding="utf-8")
    assert "protocol-spike" not in source

    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    assert imported_roots <= {"__future__", "argparse", "json", "sys", "time", "typing"}

    env = _clean_xdg_env(isolated_xdg)
    data_dir = tmp_path / "quickstart_data"
    exec_ok = new_execution_id()
    exec_err = new_execution_id()

    ok_stdin = (
        "\n".join(
            json.dumps(obj, separators=(",", ":"))
            for obj in (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "quickstart-test", "version": "0.1.0"},
                    },
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "echo_message", "arguments": {"message": "release-ok"}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "slow_lookup", "arguments": {"query": "q1", "delay_ms": 15}},
                },
            )
        )
        + "\n"
    )

    run_ok = _run_aerlog_subprocess(
        "run",
        "--execution-id",
        exec_ok,
        "--data-dir",
        str(data_dir),
        "--",
        sys.executable,
        str(script_path),
        env=env,
        stdin_text=ok_stdin,
    )
    assert run_ok.returncode == 0, run_ok.stderr
    stdout_frames = [json.loads(line) for line in run_ok.stdout.splitlines() if line.strip()]
    assert len(stdout_frames) == 4
    assert stdout_frames[2]["result"]["content"][0]["text"] == "echo:release-ok"
    assert "lookup:q1" in stdout_frames[3]["result"]["content"][0]["text"]

    # Run --error mode to exercise diagnostics failure detection cleanly.
    err_stdin = (
        "\n".join(
            json.dumps(obj, separators=(",", ":"))
            for obj in (
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "echo_message", "arguments": {"message": "fail"}},
                },
            )
        )
        + "\n"
    )
    run_err = _run_aerlog_subprocess(
        "run",
        "--execution-id",
        exec_err,
        "--data-dir",
        str(data_dir),
        "--",
        sys.executable,
        str(script_path),
        "--error",
        env=env,
        stdin_text=err_stdin,
    )
    assert run_err.returncode == 0, run_err.stderr

    listed = _run_aerlog_subprocess("list", "--data-dir", str(data_dir), "--json", env=env)
    assert listed.returncode == 0, listed.stderr
    listed_ids = {row["execution_id"] for row in json.loads(listed.stdout)["executions"]}
    assert {exec_ok, exec_err} <= listed_ids

    insp = _run_aerlog_subprocess("inspect", exec_ok, "--data-dir", str(data_dir), env=env)
    assert insp.returncode == 0, insp.stderr
    assert "AERLOG EXECUTION INSPECTOR" in insp.stdout

    tl = _run_aerlog_subprocess("timeline", exec_ok, "--data-dir", str(data_dir), env=env)
    assert tl.returncode == 0, tl.stderr
    assert "echo_message" in tl.stdout
    assert "slow_lookup" in tl.stdout

    diag = _run_aerlog_subprocess(
        "diagnose", exec_err, "--fail-on", "error", "--data-dir", str(data_dir), env=env
    )
    assert diag.returncode == 2
    assert "JSONRPC_ERROR_RESPONSE" in diag.stdout

    cass_create = _run_aerlog_subprocess(
        "cassette", "create", exec_ok, "--data-dir", str(data_dir), "--json", env=env
    )
    assert cass_create.returncode == 0, cass_create.stderr
    cass_id = json.loads(cass_create.stdout)["cassette_id"]

    cass_insp = _run_aerlog_subprocess(
        "cassette", "inspect", cass_id, "--data-dir", str(data_dir), env=env
    )
    assert cass_insp.returncode == 0, cass_insp.stderr
    assert cass_id in cass_insp.stdout

    rep = _run_aerlog_subprocess(
        "replay", exec_ok, "--fail-on-divergence", "--data-dir", str(data_dir), env=env
    )
    assert rep.returncode == 0, rep.stderr

    exp_dir = tmp_path / "exported_tests"
    exp = _run_aerlog_subprocess(
        "export",
        "test",
        exec_ok,
        "--output",
        str(exp_dir),
        "--data-dir",
        str(data_dir),
        env=env,
    )
    assert exp.returncode == 0, exp.stderr
    fixtures = list(exp_dir.glob("*.fixture.json"))
    assert len(fixtures) == 1

    verify = _run_aerlog_subprocess(
        "export",
        "verify",
        str(fixtures[0]),
        "--data-dir",
        str(data_dir),
        env=env,
    )
    assert verify.returncode == 0, verify.stderr

    # Sanity-check exported static pytest file also executes offline cleanly.
    py_tests = list(exp_dir.glob("test_*.py"))
    assert len(py_tests) == 1
    pt_res = subprocess.run(
        [sys.executable, "-m", "pytest", str(py_tests[0])],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert pt_res.returncode == 0, pt_res.stdout + pt_res.stderr
