"""Offline regression checks for reusable-workflow scanner pin discovery."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_scanner_pins.py"
spec = importlib.util.spec_from_file_location("check_scanner_pins", SCRIPT)
assert spec and spec.loader
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)
SHA = "a" * 64


def workflow(inputs: str) -> str:
    return "on:\n  workflow_call:\n    inputs:\n" + inputs + "jobs:\n  test:\n    runs-on: ubuntu-latest\n"


def pair(tool: str, version: str = "1.12.6", sha: str = SHA) -> str:
    return (
        f'      {tool}-version:\n        type: string\n        default: "{version}"\n'
        f'      {tool}-sha256:\n        type: string\n        default: "{sha}"\n'
    )


def setup(monkeypatch, tmp_path, files: dict[str, str]) -> None:
    directory = tmp_path / "workflows"
    directory.mkdir()
    for name, text in files.items():
        (directory / name).write_text(text)
    monkeypatch.setattr(scanner, "WORKFLOWS", directory)


def test_real_workflows_have_full_versions_and_no_python_runtime_pin():
    found = scanner.pins()
    assert found["tofu"]["version"] == "1.12.6"
    assert found["tofu"]["sha256"] and len(found["tofu"]["sha256"]) == 64
    assert "python" not in found
    assert "lint-python" not in found


def test_only_workflow_call_input_defaults_not_jobs_or_unpaired_python(monkeypatch, tmp_path):
    text = workflow("      python-version:\n        default: '3.13'\n" + pair("trivy"))
    text += "# unrelated usage\n# fake-version:\n#   default: '99'\n"
    text = text.replace(
        "    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    with:\n      trivy-version: '99'"
    )
    setup(monkeypatch, tmp_path, {"one.yml": text})
    assert scanner.pins() == {"trivy": {"version": "1.12.6", "sha256": SHA}}


@pytest.mark.parametrize(
    "inputs",
    [
        "      trivy-version:\n        default: '1.2.3'\n",
        "      trivy-sha256:\n        default: '" + SHA + "'\n",
        "      trivy-version:\n        default: '1.2.3'\n      trivy-sha256:\n        type: string\n",
        pair("trivy", sha="bad"),
        pair("trivy", version="${{ inputs.version }}"),
        "      custom-version:\n        default: '1.2.3'\n",
        "      custom-sha256:\n        default: '" + SHA + "'\n",
    ],
)
def test_invalid_or_incomplete_pair_fails_closed(monkeypatch, tmp_path, inputs):
    setup(monkeypatch, tmp_path, {"one.yml": workflow(inputs)})
    with pytest.raises(ValueError, match="trivy|custom"):
        scanner.pins()


def test_conflicting_versions_across_workflows_fail(monkeypatch, tmp_path):
    setup(
        monkeypatch,
        tmp_path,
        {
            "one.yml": workflow(pair("trivy", "1.2.3")),
            "two.yml": workflow(pair("trivy", "1.2.4")),
        },
    )
    with pytest.raises(ValueError, match="conflicting.*trivy|trivy.*conflicting"):
        scanner.pins()


def test_conflicting_checksums_across_workflows_fail(monkeypatch, tmp_path):
    setup(
        monkeypatch,
        tmp_path,
        {
            "one.yml": workflow(pair("trivy", sha=SHA)),
            "two.yml": workflow(pair("trivy", sha="b" * 64)),
        },
    )
    with pytest.raises(ValueError, match="conflicting trivy sha256"):
        scanner.pins()


def test_stale_mode_does_not_call_api_on_invalid_pins(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path, {"one.yml": workflow("      trivy-version:\n        default: '1.2.3'\n")})
    monkeypatch.setattr(scanner, "latest_release", lambda repo: pytest.fail("unexpected network lookup"))
    monkeypatch.setattr(sys, "argv", ["check_scanner_pins.py", "--stale"])
    assert scanner.main() == 2
    assert "trivy" in capsys.readouterr().err


def test_stale_compares_full_version_offline(monkeypatch, tmp_path, capsys):
    setup(monkeypatch, tmp_path, {"one.yml": workflow(pair("trivy", "1.12.6"))})
    monkeypatch.setattr(scanner, "latest_release", lambda repo: ("1.12.7", None))
    monkeypatch.setattr(sys, "argv", ["check_scanner_pins.py", "--stale"])
    assert scanner.main() == 1
    assert "pinned 1.12.6, latest 1.12.7" in capsys.readouterr().out
