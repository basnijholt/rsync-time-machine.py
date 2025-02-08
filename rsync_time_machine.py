#!/usr/bin/env python3
"""rsync-time-machine.py: A script for creating and managing time-stamped backups using rsync."""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import signal
import sys
import time
from datetime import datetime
from typing import TYPE_CHECKING, Callable, NamedTuple

if TYPE_CHECKING:
    from types import FrameType

APPNAME = "rsync-time-machine.py"
VERBOSE = False


class SSH(NamedTuple):
    """SSH connection details."""

    src_folder_prefix: str
    dest_folder_prefix: str
    cmd: str
    src_folder: str
    dest_folder: str
    port: str
    id_rsa: str | None


def dest_is_ssh(ssh: SSH | None) -> SSH | None:
    """Returns the SSH object only if the destination is remote."""
    return ssh if ssh and ssh.dest_folder_prefix else None


COLORS = {
    "green": "\033[92m",
    "magenta": "\033[95m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "orange": "\033[33m",
}


def style(text: str, color: str | None = None, *, bold: bool = False) -> str:
    """Return styled text."""
    color_code = COLORS.get(color, "")  # type: ignore[arg-type]
    bold_code = "\033[1m" if bold else ""
    reset_code = "\033[0m"
    return f"{bold_code}{color_code}{text}{reset_code}"


def sanitize(s: str) -> str:
    """Return a sanitized version of the string."""
    # See https://github.com/basnijholt/rsync-time-machine.py/issues/1
    return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def log(message: str, level: str = "info") -> None:
    """Log a message with the specified log level."""
    levels = {"info": "", "warning": "[WARNING] ", "error": "[ERROR] "}
    output = sys.stderr if level in {"warning", "error"} else sys.stdout
    message = sanitize(message)
    print(f"{style(APPNAME, bold=True)}: {levels[level]}{message}", file=output)


def log_info(message: str) -> None:
    """Log an info message to stdout."""
    log(message, "info")


def log_warn(message: str) -> None:
    """Log a warning message to stderr."""
    log(style(message, "orange"), "warning")


def log_error(message: str) -> None:
    """Log an error message to stderr."""
    log(style(message, "red", bold=True), "error")


def log_info_cmd(message: str, ssh: SSH | None = None) -> None:
    """Log an info message to stdout, including the SSH command if applicable."""
    if ssh is not None:
        message = f"{ssh.cmd} '{message}'"
    log_info(message)


def terminate_script(
    _signal_number: int,
    _frame: FrameType | None,
) -> None:
    """Terminate the script when CTRL+C is pressed."""
    log_info("SIGINT caught.")
    sys.exit(1)


def parse_arguments() -> argparse.Namespace:  # pragma: no cover
    """Parse command-line arguments and return the parsed arguments.

    (Replaces argument parsing part in the Bash script).
    """
    parser = argparse.ArgumentParser(
        description="A script for creating and managing time-stamped backups using rsync.",
    )
    parser.add_argument("-p", "--port", default="22", help="SSH port.")
    parser.add_argument("-i", "--id_rsa", help="Specify the private ssh key to use.")
    parser.add_argument(
        "--rsync-get-flags",
        action="store_true",
        help="Display the default rsync flags that are used for backup. If using remote drive over SSH, --compress will be added.",
    )
    parser.add_argument(
        "--rsync-set-flags",
        help="Set the rsync flags that are going to be used for backup.",
    )
    parser.add_argument(
        "--rsync-append-flags",
        help="Append the rsync flags that are going to be used for backup.",
    )
    log_dir_default = "$HOME/.rsync-time-backup"
    parser.add_argument(
        "--log-dir",
        default=log_dir_default,
        help="Set the log file directory. If this flag is set, generated files will not be managed by the script - in particular they will not be automatically deleted. Default: $HOME/.rsync-time-backup",  # noqa: E501
    )
    parser.add_argument(
        "--strategy",
        default="1:1 30:7 365:30",
        help='Set the expiration strategy. Default: "1:1 30:7 365:30" means after one day, keep one backup per day. After 30 days, keep one backup every 7 days. After 365 days keep one backup every 30 days.',  # noqa: E501
    )
    parser.add_argument(
        "--no-auto-expire",
        action="store_true",
        help="Disable automatically deleting backups when out of space. Instead, an error is logged, and the backup is aborted.",
    )
    parser.add_argument(
        "--allow-host-only",
        action="store_true",
        help="By default, the script expects a 'USER@HOST' pattern for specifying SSH connections."
        " When this flag is used, it allows for the 'HOST' pattern without a specified user."
        " This is useful if you want to use configurations from the `.ssh/config` file or rely on the current username."
        " Note: this option will not enforce SSH usage, it only broadens the accepted input formats.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the backup process without making any persistent changes.",
    )

    parser.add_argument(
        "src_folder",
        help="Source folder for backup. Format: [USER@HOST:]SOURCE",
    )
    parser.add_argument(
        "dest_folder",
        help="Destination folder for backup. Format: [USER@HOST:]DESTINATION",
    )
    parser.add_argument(
        "exclusion_file",
        nargs="?",
        help="Path to the file containing exclude patterns."
        " Cannot be used together with `--exclude-from`.",
    )
    parser.add_argument(
        "--exclude-from",
        dest="exclude_from",
        help="Path to the file containing exclude patterns."
        " Alternative to the positional `exclusion_file`."
        " Not to be used with `exclusion_file`.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output. This will slow down the backup process (in simple tests by 2x).",
    )
    args = parser.parse_args()
    # If both positional exclusion_file and optional --exclude-from are provided, raise an error
    if args.exclusion_file and args.exclude_from:
        parser.error(
            "Both positional `exclusion_file` and `--exclude-from` were"
            " provided. Please use only one of them.",
        )

    # If --exclude-from is provided, set exclusion_file to its value
    if args.exclude_from:
        args.exclusion_file = args.exclude_from

    args._auto_delete_log = args.log_dir == log_dir_default

    return args


def parse_ssh_pattern(
    folder: str,
    *,
    allow_host_only: bool = False,
) -> dict[str, str] | None:
    """Parse the source or destination folder for SSH usage."""
    pattern = r"^(?:(?P<user>[a-z0-9\._\-]+)@)?(?P<host>[A-Za-z0-9.\-]+):(?P<path>.+)$"
    match = re.match(pattern, folder)

    if match:
        result = match.groupdict()
        if not allow_host_only and result["user"] is None:
            return None
        return result
    return None


def parse_ssh(
    src_folder: str,
    dest_folder: str,
    *,
    ssh_port: str,
    id_rsa: str | None,
    allow_host_only: bool,
) -> SSH | None:
    """Parse the source and destination folders for SSH usage."""
    ssh_src = parse_ssh_pattern(src_folder, allow_host_only=allow_host_only)
    ssh_dest = parse_ssh_pattern(dest_folder, allow_host_only=allow_host_only)

    if ssh_src or ssh_dest:
        ssh = ssh_src or ssh_dest
        assert ssh is not None
        ssh_user = ssh["user"] if ssh["user"] else ""
        ssh_host = ssh["host"]
        auth = f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host
        id_rsa_opt = f"-i {id_rsa} " if id_rsa else ""
        ssh_cmd = f"ssh -p {ssh_port} {id_rsa_opt}{auth}"

        ssh_src_folder_prefix = f"{auth}:" if ssh_src else ""
        ssh_dest_folder_prefix = f"{auth}:" if ssh_dest else ""

        ssh_src_folder = ssh_src["path"] if ssh_src else src_folder
        ssh_dest_folder = ssh_dest["path"] if ssh_dest else dest_folder

        return SSH(
            ssh_src_folder_prefix,
            ssh_dest_folder_prefix,
            ssh_cmd,
            ssh_src_folder,
            ssh_dest_folder,
            ssh_port,
            id_rsa,
        )

    return None


def parse_date_to_epoch(date_str: str) -> int:
    """Parse a date string and return the Unix Epoch."""
    # Attempt to parse the date with the format YYYY-MM-DD-HHMMSS
    dt = datetime.strptime(date_str, "%Y-%m-%d-%H%M%S")  # noqa: DTZ007

    # Convert the datetime object to Unix Epoch
    return int(time.mktime(dt.timetuple()))


def find_backups(dest_folder: str, ssh: SSH | None = None) -> list[str]:
    """Return a list of all available backups in the destination folder, sorted by date.

    (Replaces 'fn_find_backups' in the Bash script).
    """
    cmd = f"find '{dest_folder}/' -maxdepth 1 -type d -name '????-??-??-??????' -prune | sort -r"
    return run_cmd(cmd, dest_is_ssh(ssh)).stdout.splitlines()


def expire_backup(
    backup_path: str,
    ssh: SSH | None,
) -> None:
    """Expire the given backup folder after checking if it's on a backup destination."""
    parent_dir = os.path.dirname(backup_path)

    # Double-check that we're on a backup destination to be completely
    # sure we're deleting the right folder
    if not find_backup_marker(parent_dir, ssh):
        log_error(f"{backup_path} is not on a backup destination - aborting.")
        sys.exit(1)

    log_info(f"Expiring {backup_path}")
    rm_dir(backup_path, ssh)


def expire_backups(
    dest_folder: str,
    expiration_strategy: str,
    backup_to_keep: str,
    ssh: SSH | None,
) -> None:
    """Expire backups according to the expiration strategy."""
    current_timestamp = int(datetime.now().timestamp())
    last_kept_timestamp = 9999999999
    backups = find_backups(dest_folder, ssh)

    # We will also keep the oldest backup
    oldest_backup_to_keep = sorted(backups)[0] if backups else None

    # Process each backup dir from the oldest to the most recent
    for backup_dir in sorted(backups):
        backup_date = os.path.basename(backup_dir)
        backup_timestamp = parse_date_to_epoch(backup_date)

        # Skip if failed to parse date...
        if backup_timestamp is None:
            log_warn(f"Could not parse date: {backup_dir}")
            continue

        if backup_dir == backup_to_keep:
            # This is the latest backup requested to be kept. We can finish pruning
            break

        if backup_dir == oldest_backup_to_keep:
            # We don't want to delete the oldest backup. It becomes the first "last kept" backup
            last_kept_timestamp = backup_timestamp
            # As we keep it, we can skip processing it and go to the next oldest one in the loop
            continue

        # Find which strategy token applies to this particular backup
        for strategy_token in sorted(expiration_strategy.split(), reverse=True):
            t = list(map(int, strategy_token.split(":")))

            # After which date (relative to today) this token applies (X) - we use seconds to get exact cut off time
            cut_off_timestamp = current_timestamp - t[0] * 86400

            # Every how many days should a backup be kept past the cut off date (Y) - we use days (not seconds)
            cut_off_interval_days = t[1]

            # If we've found the strategy token that applies to this backup
            if backup_timestamp <= cut_off_timestamp:
                # Special case: if Y is "0" we delete every time
                if cut_off_interval_days == 0:
                    expire_backup(backup_dir, ssh)
                    break

                # We calculate days number since the last kept backup
                last_kept_timestamp_days = last_kept_timestamp // 86400
                backup_timestamp_days = backup_timestamp // 86400
                interval_since_last_kept_days = (
                    backup_timestamp_days - last_kept_timestamp_days
                )

                # Check if the current backup is in the interval between
                # the last backup that was kept and Y
                # to determine what to keep/delete we use days difference
                if interval_since_last_kept_days < cut_off_interval_days:
                    # Yes: Delete that one
                    expire_backup(backup_dir, ssh)
                    # Backup deleted, no point to check shorter timespan strategies - go to the next backup
                    break

                # No: Keep it.
                # This is now the last kept backup
                last_kept_timestamp = backup_timestamp
                # And go to the next backup
                break


def backup_marker_path(folder: str) -> str:
    """Return the path to the backup marker file."""
    return os.path.join(folder, "backup.marker")


def find_backup_marker(folder: str, ssh: SSH | None = None) -> str | None:
    """Find the backup marker file in the given folder."""
    marker_path = backup_marker_path(folder)
    output = find(marker_path, dest_is_ssh(ssh))
    return marker_path if output else None


class CmdResult(NamedTuple):
    """Command result."""

    stdout: str
    stderr: str
    returncode: int


async def async_run_cmd(
    cmd: str,
    ssh: SSH | None = None,
) -> CmdResult:
    """Run a command locally or remotely."""
    if VERBOSE:
        log_info(
            f"Running {'local' if ssh is None else 'remote'} command: {style(cmd, 'green', bold=True)}",
        )

    if ssh is not None:
        process = await asyncio.create_subprocess_shell(
            f"{ssh.cmd} '{cmd}'",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    else:
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    # Should not be None because of asyncio.subprocess.PIPE
    assert process.stdout is not None, "Process stdout is None"
    assert process.stderr is not None, "Process stderr is None"

    stdout, stderr = await asyncio.gather(
        read_stream(process.stdout, log_info, "magenta"),
        read_stream(process.stderr, log_info, "red"),
    )

    await process.wait()
    assert process.returncode is not None, "Process has not returned"

    if VERBOSE and process.returncode != 0:
        msg = style(str(process.returncode), "red", bold=True)
        log_error(f"Command exit code: {msg}")
    return CmdResult(stdout, stderr, process.returncode)


async def read_stream(
    stream: asyncio.StreamReader,
    callback: Callable[[str], None],
    color: str,
) -> str:
    """Read each line from the stream and pass it to the callback."""
    output = []
    while True:
        line = await stream.readline()
        if line:
            line_str = line.decode("utf-8", "replace").rstrip()
            output.append(line_str)
            if VERBOSE:
                callback(f"Command output: {style(line_str, color, bold=True)}")
        else:
            break
    return "\n".join(output)


def run_cmd(
    cmd: str,
    ssh: SSH | None = None,
) -> CmdResult:
    """Synchronously run a command locally or remotely."""
    return asyncio.run(async_run_cmd(cmd, ssh))


def find(path: str, ssh: SSH | None = None, maxdepth: int | None = None) -> str:
    """Find files in the given path, using the `find` command."""
    cmd = f"find '{path}'"
    if maxdepth is not None:
        cmd += f" -maxdepth {maxdepth}"
    return run_cmd(cmd, ssh).stdout


def get_absolute_path(path: str, ssh: SSH | None = None) -> str:
    """Get the absolute path of the given path."""
    return run_cmd(f"cd '{path}';pwd", ssh).stdout


def mkdir(path: str, ssh: SSH | None = None) -> None:
    """Create a directory."""
    run_cmd(f"mkdir -p -- '{path}'", ssh)


def rm_file(path: str, ssh: SSH | None = None) -> None:
    """Remove a file."""
    run_cmd(f"rm -f -- '{path}'", ssh)


def rm_dir(path: str, ssh: SSH | None = None) -> None:
    """Remove a directory."""
    run_cmd(f"rm -rf -- '{path}'", ssh)


def ln(src: str, dest: str, ssh: SSH | None = None) -> None:
    """Create a symlink."""
    run_cmd(f"ln -s -- '{src}' '{dest}'", ssh)


def test_file_exists_src(path: str, ssh: SSH | None = None) -> bool:
    """Test if a file exists."""
    return run_cmd(f"test -e '{path}'", ssh).returncode == 0


def get_file_system_type(path: str, ssh: SSH | None = None) -> str:
    """Get the filesystem type of the given path."""
    lines = run_cmd(f"df -T '{path}'", ssh).stdout.split("\n")
    if len(lines) > 1:
        return lines[1].split()[1]  # filesystem type is in the second column
    return ""


def check_dest_is_backup_folder(
    dest_folder: str,
    ssh: SSH | None,
) -> None:
    """Check if the destination is a backup folder or drive."""
    marker_path = backup_marker_path(dest_folder)
    if not find_backup_marker(dest_folder, ssh):
        log_info(
            style(
                "Safety check failed - the destination does not appear to be a backup folder or drive (marker file not found).",
                "yellow",
            ),
        )
        log_info(
            style(
                "If it is indeed a backup folder, you may add the marker file by running the following command:",
                "yellow",
            ),
        )
        log_info_cmd(
            style(
                f'mkdir -p -- "{dest_folder}" ; touch "{marker_path}"',
                "green",
                bold=True,
            ),
            ssh,
        )
        sys.exit(1)


def get_link_dest_option(
    previous_dest: str | None,
    ssh: SSH | None,
) -> str:
    """Get the --link-dest option for rsync."""
    link_dest_option = ""
    if not previous_dest:
        log_info("No previous backup - creating new one.")
    else:
        previous_dest = get_absolute_path(previous_dest, ssh)
        _full_previous_dest = (
            f"{ssh.dest_folder_prefix}{previous_dest}" if ssh else previous_dest
        )
        log_info(
            style(
                f"Previous backup found - doing incremental backup from {style(_full_previous_dest, bold=True)}",
                "yellow",
            ),
        )
        link_dest_option = f"--link-dest='{previous_dest}'"
    return link_dest_option


def handle_ssh(
    src_folder: str,
    dest_folder: str,
    *,
    ssh_port: str,
    id_rsa: str | None,
    exclusion_file: str,
    allow_host_only: bool,
) -> tuple[str, str, SSH | None]:
    """Handle SSH-related things for in the `main` function."""
    ssh = parse_ssh(
        src_folder,
        dest_folder,
        ssh_port=ssh_port,
        id_rsa=id_rsa,
        allow_host_only=allow_host_only,
    )
    if ssh is not None:
        if ssh.dest_folder:
            dest_folder = ssh.dest_folder
        if ssh.src_folder:
            src_folder = ssh.src_folder

    dest_folder = dest_folder.rstrip("/") if dest_folder != "/" else dest_folder
    src_folder = src_folder.rstrip("/") if src_folder != "/" else src_folder

    if not src_folder or not dest_folder:
        log_error("Source and destination folder cannot be empty.")
        sys.exit(1)

    if (
        "'" in src_folder
        or "'" in dest_folder
        or (exclusion_file and "'" in exclusion_file)
    ):
        log_error(
            "Source and destination directories may not contain single quote characters.",
        )
        sys.exit(1)
    return (
        src_folder,
        dest_folder,
        ssh,
    )


def get_rsync_flags(
    src_folder: str,
    dest_folder: str,
    rsync_set_flags: str,
    rsync_append_flags: str,
    ssh: SSH | None,
) -> list[str]:
    """Get the rsync flags."""
    rsync_flags = [
        "-D",
        "--numeric-ids",
        "--links",
        "--hard-links",
        "--one-file-system",
        "--itemize-changes",
        "--times",
        "--recursive",
        "--perms",
        "--owner",
        "--group",
        "--stats",
        "--human-readable",
    ]

    if rsync_set_flags:
        rsync_flags = rsync_set_flags.split()

    if rsync_append_flags:
        rsync_flags += rsync_append_flags.split()

    if (
        get_file_system_type(src_folder, ssh).lower() == "fat"
        or get_file_system_type(dest_folder, dest_is_ssh(ssh)).lower() == "fat"
    ):
        log_info("File-system is a version of FAT.")
        log_info("Using the --modify-window rsync parameter with value 2.")
        rsync_flags.append("--modify-window=2")

    if ssh is not None:
        rsync_flags.append("--compress")
    return rsync_flags


def exit_if_pid_running(running_pid: str, ssh: SSH | None = None) -> None:
    """Exit if another instance of this script is already running."""
    if sys.platform == "cygwin":
        cmd = f"procps -wwfo cmd -p {running_pid} --no-headers | grep '{APPNAME}'"
        running_cmd = run_cmd(cmd, ssh)
        if running_cmd.returncode == 0:
            log_error(
                f"Previous backup task is still active - aborting (command: {running_cmd.stdout}).",
            )
            sys.exit(1)
    else:
        ps_flags = "-axp" if sys.platform.startswith("netbsd") else "-p"
        cmd = f"ps {ps_flags} {running_pid} -o 'command' | grep '{APPNAME}'"
        if run_cmd(cmd).stdout:
            log_error("Previous backup task is still active - aborting.")
            sys.exit(1)


def handle_still_running_or_failed_or_interrupted_backup(
    inprogress_file: str,
    mypid: int,
    dest: str,
    dest_folder: str,
    previous_dest: str | None,
    ssh: SSH | None,
) -> None:
    """Handle cases when backup is still running or failed or interrupted backup."""
    if not find(inprogress_file, ssh):
        return

    running_pid = run_cmd(f"cat {inprogress_file}", ssh).stdout
    exit_if_pid_running(running_pid, ssh)

    if previous_dest:
        # - Last backup is moved to current backup folder so that it can be resumed.
        # - 2nd to last backup becomes last backup.
        ssh_dest_folder_prefix = ssh.dest_folder_prefix if ssh else ""
        log_info(
            f"{ssh_dest_folder_prefix}{inprogress_file} already exists - the previous backup failed or was interrupted. Backup will resume from there.",  # noqa: E501
        )
        run_cmd(f"mv -- {previous_dest} {dest}", ssh)
        backups = find_backups(dest_folder, ssh)
        previous_dest = backups[1] if len(backups) > 1 else ""

        # Update PID to current process to avoid multiple concurrent resumes
        run_cmd(f"echo {mypid} > {inprogress_file}", ssh)


def deal_with_no_space_left(
    log_file: str,
    dest_folder: str,
    *,
    ssh: SSH | None,
    auto_expire: bool,
) -> bool:
    """Deal with no space left on device."""
    with open(log_file) as f:
        log_data = f.read()

    no_space_left = re.search(
        r"No space left on device \(28\)|Result too large \(34\)",
        log_data,
    )

    if no_space_left:
        if not auto_expire:
            log_error(
                "No space left on device, and automatic purging of old backups is disabled.",
            )
            sys.exit(1)

        log_warn(
            "No space left on device - removing oldest backup and resuming.",
        )
        backups = find_backups(dest_folder, ssh)
        if len(backups) <= 1:
            log_error("No space left on device, and no old backup to delete.")
            sys.exit(1)

        expire_backup(sorted(backups)[-1], ssh)
        return True
    return False


def check_rsync_errors(
    log_file: str,
    auto_delete_log: bool,  # noqa: FBT001
) -> None:
    """Check rsync errors."""
    with open(log_file) as f:
        log_data = f.read()
    if "rsync error:" in log_data:
        log_error(
            f"Rsync reported an error. Run this command for more details: grep -E 'rsync:|rsync error:' '{log_file}'",
        )
    elif "rsync:" in log_data:
        log_warn(
            f"Rsync reported a warning. Run this command for more details: grep -E 'rsync:|rsync error:' '{log_file}'",
        )
    else:
        log_info(style("Backup completed without errors.", "magenta"))
        if auto_delete_log:
            os.remove(log_file)


def now_str() -> str:
    """Return current date and time as string in format YYYY-MM-DD-HHMMSS."""
    return datetime.now().strftime("%Y-%m-%d-%H%M%S")


def start_backup(
    src_folder: str,
    dest: str,
    exclusion_file: str,
    inprogress_file: str,
    link_dest_option: str,
    rsync_flags: list[str],
    log_dir: str,
    mypid: int,
    ssh: SSH | None,
    now: str,
) -> str:
    """Start backup."""
    log_file = os.path.join(
        log_dir,
        f"{now}.log",
    )
    if ssh is not None:
        src_folder = f"{ssh.src_folder_prefix}{src_folder}"
        dest = f"{ssh.dest_folder_prefix}{dest}"
    log_info(style("Starting backup...", "yellow"))
    log_info(f"From: {style(src_folder, bold=True)}/")
    log_info(f"To:   {style(dest, bold=True)}/")

    cmd = "rsync"
    if ssh is not None:
        id_rsa_option = f"-i {ssh.id_rsa} " if ssh.id_rsa else ""
        cmd = f"{cmd} -e 'ssh -p {ssh.port} {id_rsa_option}-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'"

    cmd = f"{cmd} {' '.join(rsync_flags)}"
    cmd = f"{cmd} --log-file '{log_file}'"
    if exclusion_file:
        cmd = f"{cmd} --exclude-from '{exclusion_file}'"

    cmd = f"{cmd} {link_dest_option}"
    cmd = f"{cmd} -- '{src_folder}/' '{dest}/'"

    log_info(style("Running command:", bold=True))
    log_info(style(cmd, "green"))

    run_cmd(f"echo {mypid} > {inprogress_file}", ssh)

    run_cmd(cmd)
    return log_file


def backup(
    src_folder: str,
    dest_folder: str,
    *,
    exclusion_file: str,
    log_dir: str,
    auto_delete_log: bool,
    expiration_strategy: str,
    auto_expire: bool,
    port: str,
    id_rsa: str,
    rsync_set_flags: str,
    rsync_append_flags: str,
    rsync_get_flags: bool,
    allow_host_only: bool,
    dry_run: bool,
) -> None:
    """Perform backup of src_folder to dest_folder."""
    (
        src_folder,
        dest_folder,
        ssh,
    ) = handle_ssh(
        src_folder,
        dest_folder,
        ssh_port=port,
        id_rsa=id_rsa,
        exclusion_file=exclusion_file,
        allow_host_only=allow_host_only,
    )

    if not test_file_exists_src(src_folder, ssh):
        log_error(f"Source folder '{src_folder}' does not exist - aborting.")
        sys.exit(1)

    check_dest_is_backup_folder(dest_folder, dest_is_ssh(ssh))

    now = now_str()
    dest = os.path.join(dest_folder, now)
    _backups = sorted(find_backups(dest_folder, ssh), reverse=True)
    previous_dest = _backups[0] if _backups else None
    inprogress_file = os.path.join(dest_folder, "backup.inprogress")
    mypid = os.getpid()

    if not os.path.exists(log_dir):
        log_info(f"Creating log folder in '{log_dir}'...")
        os.makedirs(log_dir)

    handle_still_running_or_failed_or_interrupted_backup(
        inprogress_file,
        mypid,
        dest,
        dest_folder,
        previous_dest,
        ssh,
    )

    rsync_flags = get_rsync_flags(
        src_folder,
        dest_folder,
        rsync_set_flags,
        rsync_append_flags,
        ssh,
    )

    if "-n" in rsync_flags or "--dry-run" in rsync_flags:
        dry_run = True
        log_info(
            f"Dry-run detected in rsync flags - setting {style('--dry-run', 'green')}.",
        )
    elif dry_run:
        rsync_flags.append("--dry-run")
    if dry_run:
        log_info(
            f"Dry-run mode enabled: {style('no changes will be persisted', 'orange')}.",
        )

    if rsync_get_flags:
        flags = " ".join(rsync_flags)
        log_info(f"Rsync flags:\n{style(flags, 'yellow', bold=True)}")
        sys.exit(0)

    for _ in range(100):  # max 100 retries when no space left
        link_dest_option = get_link_dest_option(previous_dest, ssh)

        if not find(dest, ssh, maxdepth=0):
            _full_dest = style(f"{ssh.cmd if ssh else ''}{dest}", bold=True)
            log_info(f"Creating destination {_full_dest}")
            mkdir(dest, ssh)

        expire_backups(
            dest_folder,
            expiration_strategy,
            previous_dest if previous_dest else dest,
            ssh,
        )

        log_file = start_backup(
            src_folder,
            dest,
            exclusion_file,
            inprogress_file,
            link_dest_option,
            rsync_flags,
            log_dir,
            mypid,
            ssh,
            now,
        )
        retry = deal_with_no_space_left(
            log_file,
            dest_folder,
            ssh=ssh,
            auto_expire=auto_expire,
        )
        if not retry:
            break

    check_rsync_errors(log_file, auto_delete_log)

    if dry_run:
        # In dry-run mode, clean up any temporary artifacts
        # and exit without updating the "latest" symlink.
        rm_dir(dest, ssh)
        rm_file(inprogress_file, ssh)
        log_info("Dry run complete - no backup was saved.")
        return

    rm_file(os.path.join(dest_folder, "latest"), dest_is_ssh(ssh))
    ln(
        os.path.basename(dest),
        os.path.join(dest_folder, "latest"),
        dest_is_ssh(ssh),
    )

    rm_file(inprogress_file, ssh)


def main() -> None:
    """Main function."""
    args = parse_arguments()
    global VERBOSE
    VERBOSE = args.verbose
    signal.signal(signal.SIGINT, lambda n, f: terminate_script(n, f))
    backup(
        src_folder=args.src_folder,
        dest_folder=args.dest_folder,
        exclusion_file=args.exclusion_file,
        log_dir=os.path.expandvars(os.path.expanduser(args.log_dir)),
        auto_delete_log=args._auto_delete_log,
        expiration_strategy=args.strategy,
        auto_expire=not args.no_auto_expire,
        port=args.port,
        id_rsa=args.id_rsa,
        rsync_set_flags=args.rsync_set_flags,
        rsync_append_flags=args.rsync_append_flags,
        rsync_get_flags=args.rsync_get_flags,
        allow_host_only=args.allow_host_only,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
