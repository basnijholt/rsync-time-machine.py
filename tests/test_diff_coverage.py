"""Additional tests ensuring full coverage of the PR diff."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture()
def rtm() -> Any:
    """Reload the module so coverage tracks executed lines precisely."""

    module = importlib.import_module("rsync_time_machine")
    return importlib.reload(module)


def test_prepare_exclusion_file_missing_file(tmp_path: Path, rtm: Any) -> None:
    """Missing exclusion files should trigger a fatal error."""

    module = rtm
    missing = tmp_path / "does-not-exist.txt"
    with pytest.raises(SystemExit):
        module.prepare_exclusion_file(str(missing))


def test_prepare_exclusion_file_noop_cleanup(tmp_path: Path, rtm: Any) -> None:
    """A newline-terminated exclusion file is returned untouched."""

    module = rtm
    exclusion = tmp_path / "exclude.txt"
    exclusion.write_bytes(b"pattern\n")

    prepared, cleanup = module.prepare_exclusion_file(str(exclusion))

    assert prepared == str(exclusion)
    cleanup()  # ensure the no-op path is executed
    assert exclusion.exists()


def test_prepare_exclusion_file_appends_newline_and_cleans(tmp_path: Path, rtm: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Files without a trailing newline are copied and cleaned up after use."""

    module = rtm
    exclusion = tmp_path / "exclude.txt"
    exclusion.write_bytes(b"pattern")

    created_paths: list[Path] = []

    original_mkstemp = module.tempfile.mkstemp

    def fake_mkstemp(prefix: str, suffix: str) -> tuple[int, str]:
        fd, path = original_mkstemp(prefix=prefix, suffix=suffix, dir=tmp_path)
        created_paths.append(Path(path))
        return fd, path

    monkeypatch.setattr(module.tempfile, "mkstemp", fake_mkstemp)

    prepared, cleanup = module.prepare_exclusion_file(str(exclusion))

    prepared_path = Path(prepared)
    assert prepared_path in created_paths
    assert prepared_path.read_bytes() == b"pattern\n"

    cleanup()
    for path in created_paths:
        assert not path.exists()


def test_normalize_pid_variants(rtm: Any) -> None:
    """Exercise the PID normalisation helper across its branches."""

    module = rtm
    assert module.normalize_pid("", None) is None
    assert module.normalize_pid("0", None) is None

    current_pid = os.getpid()
    assert module.normalize_pid(str(current_pid), None) is None

    fake_ssh = module.SSH("", "", "", "", "", "22", None)
    assert module.normalize_pid(str(current_pid), fake_ssh) == current_pid

    assert module.normalize_pid("1234", None) == 1234


def test_exit_if_pid_running_invokes_ps(rtm: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Valid PIDs should lead to a ps invocation with the stripped PID string."""

    module = rtm
    commands: list[str] = []

    def fake_run_cmd(cmd: str, ssh: Any | None = None) -> Any:
        commands.append(cmd)
        return module.CmdResult("", "", 0)

    monkeypatch.setattr(module, "run_cmd", fake_run_cmd)

    module.exit_if_pid_running(" 42 ")

    expected = f"ps -p 42 -o 'command' | grep '{module.APPNAME}'"
    assert expected in commands


def test_exit_if_pid_running_detects_active_process(rtm: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A matching process triggers an early exit."""

    module = rtm

    def fake_run_cmd(cmd: str, ssh: Any | None = None) -> Any:
        if cmd.startswith("ps "):
            return module.CmdResult("pytest", "", 0)
        return module.CmdResult("", "", 0)

    monkeypatch.setattr(module, "run_cmd", fake_run_cmd)

    with pytest.raises(SystemExit):
        module.exit_if_pid_running("4242")


def test_exit_if_pid_running_cygwin_branch(rtm: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The cygwin branch should use the normalised PID and exit when active."""

    module = rtm
    commands: list[str] = []

    monkeypatch.setattr(module.sys, "platform", "cygwin")

    def fake_run_cmd(cmd: str, ssh: Any | None = None) -> Any:
        commands.append(cmd)
        return module.CmdResult("", "", 0)

    monkeypatch.setattr(module, "run_cmd", fake_run_cmd)

    with pytest.raises(SystemExit):
        module.exit_if_pid_running("0100")

    expected = f"procps -wwfo cmd -p 100 --no-headers | grep '{module.APPNAME}'"
    assert expected in commands


def test_start_backup_cleans_temp_exclusion_on_failure(tmp_path: Path, rtm: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """start_backup removes temporary exclude files even when rsync fails."""

    module = rtm
    src = tmp_path / "src"
    dest = tmp_path / "dest"
    log_dir = tmp_path / "logs"
    src.mkdir()
    dest.mkdir()
    log_dir.mkdir()

    exclusion = tmp_path / "exclude.txt"
    exclusion.write_text("pattern")

    created_paths: list[Path] = []

    original_mkstemp = module.tempfile.mkstemp

    def fake_mkstemp(prefix: str, suffix: str) -> tuple[int, str]:
        fd, path = original_mkstemp(prefix=prefix, suffix=suffix, dir=tmp_path)
        created_paths.append(Path(path))
        return fd, path

    monkeypatch.setattr(module.tempfile, "mkstemp", fake_mkstemp)

    def fake_run_cmd(cmd: str, ssh: Any | None = None) -> Any:
        if cmd.startswith("echo"):
            _, path = cmd.split(">", maxsplit=1)
            Path(path.strip().strip("'\"")).write_text(str(os.getpid()))
            return module.CmdResult("", "", 0)
        raise RuntimeError("rsync failed")

    monkeypatch.setattr(module, "run_cmd", fake_run_cmd)

    with pytest.raises(RuntimeError, match="rsync failed"):
        module.start_backup(
            src_folder=str(src),
            dest=str(dest),
            exclusion_file=str(exclusion),
            inprogress_file=str(dest / "backup.inprogress"),
            link_dest_option="",
            rsync_flags=["-a"],
            log_dir=str(log_dir),
            mypid=os.getpid(),
            ssh=None,
            now="2025-10-13-211815",
        )

    for path in created_paths:
        assert not path.exists()


def test_deal_with_no_space_left_handles_non_utf8(tmp_path: Path, rtm: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-UTF8 log content is parsed safely when space runs out."""

    module = rtm
    log_file = tmp_path / "backup.log"
    log_file.write_bytes(b"\xffNo space left on device (28)")

    monkeypatch.setattr(module, "find_backups", lambda dest, ssh: ["a", "b"])

    expired: list[str] = []

    def fake_expire(folder: str, ssh: Any) -> None:
        expired.append(folder)

    monkeypatch.setattr(module, "expire_backup", fake_expire)
    monkeypatch.setattr(module, "log_warn", lambda message: None)
    monkeypatch.setattr(module, "log_error", lambda message: None)

    result = module.deal_with_no_space_left(
        log_file=str(log_file),
        dest_folder=str(tmp_path),
        ssh=None,
        auto_expire=True,
    )

    assert result is True
    assert expired


def test_check_rsync_errors_handles_non_utf8_error(tmp_path: Path, rtm: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Log parsing tolerates undecodable bytes when reporting rsync errors."""

    module = rtm
    log_file = tmp_path / "rsync.log"
    log_file.write_bytes(b"\xffrsync error: something broke")

    messages: list[str] = []

    monkeypatch.setattr(module, "log_error", lambda message: messages.append(message))

    module.check_rsync_errors(str(log_file), auto_delete_log=False)

    assert messages and "rsync error" in messages[0]

