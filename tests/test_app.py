"""Test suite for `rsync-time-machine.py`."""

from __future__ import annotations

import os
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator
from unittest.mock import Mock, patch

import pytest

import rsync_time_machine
from rsync_time_machine import (
    SSH,
    backup,
    backup_marker_path,
    check_dest_is_backup_folder,
    expire_backups,
    find,
    find_backup_marker,
    find_backups,
    get_absolute_path,
    get_link_dest_option,
    handle_ssh,
    mkdir,
    parse_ssh,
    parse_ssh_pattern,
    rm_dir,
    run_cmd,
)

rsync_time_machine.VERBOSE = True


def test_parse_ssh_pattern() -> None:
    """Test the parse_ssh_pattern function."""
    assert parse_ssh_pattern("user@example.com:/path/to/folder") == {
        "user": "user",
        "host": "example.com",
        "path": "/path/to/folder",
    }
    assert parse_ssh_pattern("user@example.com:") is None
    assert parse_ssh_pattern("/path/to/folder") is None

    for allow_host_only in [True, False]:
        assert parse_ssh_pattern(
            "user@host:/path/to/folder",
            allow_host_only=allow_host_only,
        ) == {"user": "user", "host": "host", "path": "/path/to/folder"}
        assert parse_ssh_pattern(
            "user@host:path/to/folder",
            allow_host_only=allow_host_only,
        ) == {"user": "user", "host": "host", "path": "path/to/folder"}
        assert (
            parse_ssh_pattern(
                "user@host:",
                allow_host_only=allow_host_only,
            )
            is None
        )
    assert parse_ssh_pattern("host:/path/to/folder", allow_host_only=True) == {
        "user": None,
        "host": "host",
        "path": "/path/to/folder",
    }
    assert parse_ssh_pattern("host:path/to/folder", allow_host_only=True) == {
        "user": None,
        "host": "host",
        "path": "path/to/folder",
    }
    assert parse_ssh_pattern("host:", allow_host_only=True) is None
    assert parse_ssh_pattern("host:path/to/folder", allow_host_only=False) is None
    assert parse_ssh_pattern("host:/path/to/folder", allow_host_only=False) is None
    assert parse_ssh_pattern("host:", allow_host_only=False) is None
    assert parse_ssh_pattern("invalid pattern") is None


def test_parse_ssh() -> None:
    """Test the parse_ssh function."""
    ssh = parse_ssh(
        "user@example.com:/path/to/src",
        "user@example.com:/path/to/dest",
        ssh_port="22",
        id_rsa=None,
        allow_host_only=False,
    )
    assert ssh == SSH(
        "user@example.com:",
        "user@example.com:",
        "ssh -p 22 user@example.com",
        "/path/to/src",
        "/path/to/dest",
        "22",
        None,
    )

    ssh = parse_ssh(
        "user@example.com:/path/to/src",
        "/path/to/dest",
        ssh_port="22",
        id_rsa=None,
        allow_host_only=False,
    )
    assert ssh == SSH(
        "user@example.com:",
        "",
        "ssh -p 22 user@example.com",
        "/path/to/src",
        "/path/to/dest",
        "22",
        None,
    )

    ssh = parse_ssh(
        "/path/to/src",
        "user@example.com:/path/to/dest",
        ssh_port="22",
        id_rsa=None,
        allow_host_only=False,
    )
    assert ssh == SSH(
        "",
        "user@example.com:",
        "ssh -p 22 user@example.com",
        "/path/to/src",
        "/path/to/dest",
        "22",
        None,
    )

    assert (
        parse_ssh(
            "/path/to/src",
            "/path/to/dest",
            ssh_port="22",
            id_rsa=None,
            allow_host_only=False,
        )
        is None
    )

    ssh = parse_ssh(
        "host:/path/to/src",
        "host:/path/to/dest",
        ssh_port="22",
        id_rsa=None,
        allow_host_only=True,
    )
    assert ssh == SSH(
        "host:",
        "host:",
        "ssh -p 22 host",
        "/path/to/src",
        "/path/to/dest",
        "22",
        None,
    )

    assert (
        parse_ssh(
            "host:/path/to/src",
            "host:/path/to/dest",
            ssh_port="22",
            id_rsa=None,
            allow_host_only=False,
        )
        is None
    )


def test_find_backups(tmp_path: Path) -> None:
    """Test the find_backups function."""
    backups = [
        "2023-05-10-175347",
        "2023-05-11-175347",
        "2023-05-12-175347",
    ]
    for _backup in backups:
        (tmp_path / _backup).mkdir()
    full_paths = [(tmp_path / _backup).resolve() for _backup in backups]
    found_backups = find_backups(str(tmp_path), None)
    assert sorted([Path(p) for p in found_backups]) == sorted(full_paths)


def test_backup_marker_path() -> None:
    """Test the backup_marker_path function."""
    assert backup_marker_path("/path/to/folder") == "/path/to/folder/backup.marker"


def test_find_backup_marker(tmp_path: Path) -> None:
    """Test the find_backup_marker function."""
    marker_path = backup_marker_path(str(tmp_path))
    assert find_backup_marker(str(tmp_path), None) is None

    Path(marker_path).touch()
    assert find_backup_marker(str(tmp_path), None) == marker_path


def test_run_cmd() -> None:
    """Test the run_cmd function."""
    result = run_cmd("echo 'Hello, World!'")
    assert result.returncode == 0
    assert result.stdout.strip() == "Hello, World!"
    assert not result.stderr.strip()


def test_find(tmp_path: Path) -> None:
    """Test the find function."""
    path = tmp_path / "testfile.txt"
    path.touch()
    assert find(str(path), None) == str(path)
    assert find(str(tmp_path), None, maxdepth=0) == str(tmp_path)


def test_get_absolute_path(tmp_path: Path) -> None:
    """Test the get_absolute_path function."""
    path = tmp_path / "testfolder"
    path.mkdir()
    assert get_absolute_path(str(path), None) == str(path.resolve())


def test_mkdir(tmp_path: Path) -> None:
    """Test the mkdir function."""
    path = tmp_path / "testfolder"
    assert not path.exists()
    mkdir(str(path), None)
    assert path.exists()


def test_rm_dir(tmp_path: Path) -> None:
    """Test the rm_dir function."""
    path = tmp_path / "testfolder"
    path.mkdir()
    assert path.exists()
    rm_dir(str(path), None)
    assert not path.exists()


def test_check_dest_is_backup_folder(tmp_path: Path) -> None:
    """Test the check_dest_is_backup_folder function."""
    # Create a backup.marker file
    marker_path = backup_marker_path(str(tmp_path))
    Path(marker_path).touch()

    # It should pass with the backup.marker file
    check_dest_is_backup_folder(str(tmp_path), None)

    # Remove the marker file and it should raise a SystemExit
    os.remove(marker_path)
    with pytest.raises(SystemExit):
        check_dest_is_backup_folder(str(tmp_path), None)


def test_get_link_dest_option(tmp_path: Path) -> None:
    """Test the get_link_dest_option function."""
    previous_dest = tmp_path / "previous"
    previous_dest.mkdir()
    assert (
        get_link_dest_option(str(previous_dest), None)
        == f"--link-dest='{previous_dest}'"
    )
    assert not get_link_dest_option(None, None)


def test_handle_ssh() -> None:
    """Test the handle_ssh function."""
    src_folder, dest_folder, ssh = handle_ssh(
        "user@example.com:/path/to/src",
        "user@example.com:/path/to/dest",
        ssh_port="22",
        id_rsa=None,
        exclusion_file="exclusion_file",
        allow_host_only=False,
    )
    assert src_folder == "/path/to/src"
    assert dest_folder == "/path/to/dest"
    assert ssh == SSH(
        "user@example.com:",
        "user@example.com:",
        "ssh -p 22 user@example.com",
        "/path/to/src",
        "/path/to/dest",
        "22",
        None,
    )

    src_folder, dest_folder, ssh = handle_ssh(
        "/path/to/src",
        "/path/to/dest",
        ssh_port="22",
        id_rsa="",
        exclusion_file="exclusion_file",
        allow_host_only=False,
    )
    assert src_folder == "/path/to/src"
    assert dest_folder == "/path/to/dest"
    assert ssh is None


def test_expire_backups(tmp_path: Path) -> None:
    """Test the expire_backups function."""
    backups = [
        "2023-05-06-135347",
        "2023-05-06-145347",
        "2023-05-06-155347",
        "2023-05-06-165347",
        "2023-05-07-175347",
    ]
    for _backup in backups:
        (tmp_path / _backup).mkdir()

    # Create a backup.marker file
    Path(backup_marker_path(str(tmp_path))).touch()

    # Keep only one backup from 2023-05-06
    expire_backups(str(tmp_path), "1:1", backups[0], None)
    for _backup in backups[1:-1]:
        assert not (tmp_path / _backup).exists()
    assert (tmp_path / backups[0]).exists()
    # Always keep the latest backup
    assert (tmp_path / backups[-1]).exists()


@contextmanager
def patch_now_str(
    seconds: int = 0,
    days: int = 0,
    hours: int = 0,
    minutes: int = 0,
) -> Iterator[Mock]:
    """Patch the now_str function to return a future/past time."""
    time_delta = timedelta(seconds=seconds, days=days, hours=hours, minutes=minutes)
    with patch("rsync_time_machine.now_str") as mock_now:
        now = datetime.now()
        future_time = now + time_delta
        mock_now.return_value = future_time.strftime("%Y-%m-%d-%H%M%S")
        yield mock_now


def assert_n_backups(dest_folder: str | Path, n_expected: int) -> None:
    """Assert the number of backups in the destination folder."""
    assert len(find_backups(str(dest_folder), None)) == n_expected


def test_backup(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Test the backup function."""
    src_folder = tmp_path / "src"
    dest_folder = tmp_path / "dest"
    src_folder.mkdir()
    dest_folder.mkdir()
    (src_folder / "file.txt").write_text("Hello, World!")

    kw = {
        "src_folder": str(src_folder),
        "dest_folder": str(dest_folder),
        "exclusion_file": "",
        "log_dir": str(tmp_path / "logs"),
        "auto_delete_log": True,
        "expiration_strategy": "1:1",
        "auto_expire": True,
        "port": "22",
        "id_rsa": "",
        "rsync_set_flags": "",
        "rsync_append_flags": "",
        "rsync_get_flags": False,
        "allow_host_only": False,
    }
    # Tests backup with no backup.marker file
    with pytest.raises(SystemExit):
        backup(**kw)  # type: ignore[arg-type]
    captured = capsys.readouterr()
    assert "Safety check failed - the destination does not appear" in captured.out

    # Create a backup.marker file
    Path(backup_marker_path(str(dest_folder))).touch()

    # Run the backup
    # Note: patch the of all the backup calls to
    #       ensure they will not have the same timestamp
    with patch_now_str(seconds=-60):
        backup(**kw)  # type: ignore[arg-type]

    # Check the output
    captured = capsys.readouterr()
    assert "No previous backup - creating new one." in captured.out

    # Ensure there is now 1 backup
    assert_n_backups(dest_folder, 1)

    # Check that the backup was created
    assert (dest_folder / "latest" / "file.txt").exists()
    assert (dest_folder / "latest" / "file.txt").read_text() == "Hello, World!"
    dest_all_files = list(dest_folder.glob("*"))
    n_files = 3  # latest, backup.marker, YYYY-MM-DD-HHMMSS folder
    assert len(dest_all_files) == n_files

    # Check that the log folder was created
    assert (tmp_path / "logs").exists()

    # Test whether handle_still_running_or_failed_or_interrupted_backup writes PID

    # Create a backup.inprogress file with some random PID
    (dest_folder / "backup.inprogress").write_text("0")

    # Run the backup again but cancel early
    with patch("rsync_time_machine.get_rsync_flags") as mock_get_rsync_flags:
        mock_get_rsync_flags.side_effect = Exception("Break out early")
        with pytest.raises(Exception, match="Break out early"), patch_now_str(
            seconds=-40,
        ):
            backup(**kw)  # type: ignore[arg-type]

    # Ensure there is now still only 1 backup
    assert_n_backups(dest_folder, 1)

    mypid = os.getpid()
    assert (dest_folder / "backup.inprogress").read_text().strip() == str(mypid)

    # Run backup again and check that the backup.inprogress file is gone
    with patch_now_str(seconds=-20):
        backup(**kw)  # type: ignore[arg-type]
    assert not (dest_folder / "backup.inprogress").exists()

    # Now there is still only 1 backup, because the previous
    # backup was interrupted and
    # then handle_still_running_or_failed_or_interrupted_backup
    # moves the existing backup to a new timestamp and continues
    assert_n_backups(dest_folder, 1)

    # Test exclusion file
    (src_folder / "file2.txt").write_text("Hello, World!")
    (src_folder / "file3.txt").write_text("Hello, World!")
    exclusion_file = tmp_path / "exclusion_file.txt"
    exclusion_file.write_text("file2.txt")
    with patch_now_str(seconds=0):
        new_kw = dict(kw, exclusion_file=str(tmp_path / "exclusion_file.txt"))
        backup(**new_kw)  # type: ignore[arg-type]
    assert not (dest_folder / "latest" / "file2.txt").exists()
    assert (dest_folder / "latest" / "file3.txt").exists()
    assert_n_backups(dest_folder, 2)


def test_backup_with_non_utf8_filename(tmp_path: Path) -> None:
    """Test the backup function with a non-UTF8 filename.

    Reproduces https://github.com/basnijholt/rsync-time-machine.py/issues/1
    """
    src_folder = tmp_path / "src"
    dest_folder = tmp_path / "dest"
    src_folder.mkdir()
    dest_folder.mkdir()

    # Create a folder and files with a non-UTF8 filename
    folder = "TEST-UTF8"
    (src_folder / folder).mkdir()

    # Create composed and decomposed form of 'î'
    composed_filename = unicodedata.normalize("NFC", "Möîso1.rtf")
    decomposed_filename = unicodedata.normalize("NFD", "Möîso2.rtf")

    (src_folder / folder / composed_filename).write_text("Hello, World!")
    (src_folder / folder / decomposed_filename).write_text("Hello, World!")

    kw = {
        "src_folder": str(src_folder),
        "dest_folder": str(dest_folder),
        "exclusion_file": "",
        "log_dir": str(tmp_path / "logs"),
        "auto_delete_log": True,
        "expiration_strategy": "1:1",
        "auto_expire": True,
        "port": "22",
        "id_rsa": "",
        "rsync_set_flags": "",
        "rsync_append_flags": "",
        "rsync_get_flags": False,
        "allow_host_only": False,
    }

    # Create a backup.marker file
    Path(backup_marker_path(str(dest_folder))).touch()

    # Run the backup
    backup(**kw)  # type: ignore[arg-type]

    # Check that the backup was created
    for filename in [composed_filename, decomposed_filename]:
        assert (dest_folder / "latest" / folder / filename).exists()
        assert (
            dest_folder / "latest" / folder / filename
        ).read_text() == "Hello, World!"
