#!/usr/bin/env python3
"""rsync-time-machine.py: A script for creating and managing time-stamped backups using rsync."""
import argparse
import os
import re
import signal
import subprocess
import sys
import time
from contextlib import suppress
from datetime import datetime
from typing import List, NamedTuple, Optional, Tuple

with suppress(ImportError):
    from rich import print

# -----------------------------------------------------------------------------
# Log functions
# -----------------------------------------------------------------------------


def log_info(appname: str, message: str) -> None:
    """Log an info message to stdout."""
    print(f"{appname}: {message}")


def log_warn(appname: str, message: str) -> None:
    """Log a warning message to stderr."""
    print(f"{appname}: [WARNING] {message}", file=sys.stderr)


def log_error(appname: str, message: str) -> None:
    """Log an error message to stderr."""
    print(f"{appname}: [ERROR] {message}", file=sys.stderr)


def log_info_cmd(appname: str, message: str, ssh_cmd: Optional[str]) -> None:
    """Log an info message to stdout, including the SSH command if applicable."""
    if ssh_cmd:
        print(f"{appname}: {ssh_cmd} '{message}'")
    else:
        print(f"{appname}: {message}")


# -----------------------------------------------------------------------------
# Make sure everything really stops when CTRL+C is pressed
# -----------------------------------------------------------------------------


def terminate_script(appname: str, signal_number: int, frame) -> None:
    """Terminate the script when CTRL+C is pressed."""
    log_info(appname, "SIGINT caught.")
    sys.exit(1)


# -----------------------------------------------------------------------------
# Small utility functions for reducing code duplication
# -----------------------------------------------------------------------------


def parse_arguments() -> argparse.Namespace:
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
    parser.add_argument(
        "--log-dir",
        default="$HOME/.rsync-time-backup",
        help="Set the log file directory. If this flag is set, generated files will not be managed by the script - in particular they will not be automatically deleted. Default: $HOME/.rsync-time-backup",
    )
    parser.add_argument(
        "--strategy",
        default="1:1 30:7 365:30",
        help='Set the expiration strategy. Default: "1:1 30:7 365:30" means after one day, keep one backup per day. After 30 days, keep one backup every 7 days. After 365 days keep one backup every 30 days.',
    )
    parser.add_argument(
        "--no-auto-expire",
        action="store_true",
        help="Disable automatically deleting backups when out of space. Instead, an error is logged, and the backup is aborted.",
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
        help="Path to the file containing exclude patterns.",
    )

    return parser.parse_args()


def parse_date(date_str: str) -> int:
    """Parse a date string and return the Unix Epoch."""
    # Attempt to parse the date with the format YYYY-MM-DD-HHMMSS
    dt = datetime.strptime(date_str, "%Y-%m-%d-%H%M%S")

    # Convert the datetime object to Unix Epoch
    epoch = int(time.mktime(dt.timetuple()))

    return epoch


def find_backups(dest_folder: str, ssh_cmd: Optional[str]) -> list[str]:
    """Return a list of all available backups in the destination folder, sorted by date.
    (Replaces 'fn_find_backups' in the Bash script).
    """
    cmd = f"find '{dest_folder}/' -maxdepth 1 -type d -name '????-??-??-??????' -prune | sort -r"
    return run_cmd(cmd, ssh_cmd).stdout.splitlines()


def expire_backup(
    backup_path: str,
    appname: str,
    ssh_cmd: Optional[str],
) -> None:
    """Expire the given backup folder after checking if it's on a backup destination."""
    parent_dir = os.path.dirname(backup_path)

    # Double-check that we're on a backup destination to be completely
    # sure we're deleting the right folder
    if not find_backup_marker(parent_dir, ssh_cmd):
        log_error(appname, f"{backup_path} is not on a backup destination - aborting.")
        sys.exit(1)

    log_info(appname, f"Expiring {backup_path}")
    rm_dir(backup_path, ssh_cmd)


def expire_backups(
    dest_folder: str,
    appname: str,
    expiration_strategy: str,
    backup_to_keep: str,
    ssh_cmd: Optional[str],
) -> None:
    """Expire backups according to the expiration strategy."""
    current_timestamp = int(datetime.now().timestamp())
    last_kept_timestamp = 9999999999
    backups = find_backups(dest_folder, ssh_cmd)

    # We will also keep the oldest backup
    oldest_backup_to_keep = sorted(backups)[0]

    # Process each backup dir from the oldest to the most recent
    for backup_dir in sorted(backups):
        backup_date = os.path.basename(backup_dir)
        backup_timestamp = parse_date(backup_date)

        # Skip if failed to parse date...
        if backup_timestamp is None:
            log_warn(appname, f"Could not parse date: {backup_dir}")
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
                    expire_backup(backup_dir, appname, ssh_cmd)
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
                    expire_backup(backup_dir, appname, ssh_cmd)
                    # Backup deleted, no point to check shorter timespan strategies - go to the next backup
                    break

                else:
                    # No: Keep it.
                    # This is now the last kept backup
                    last_kept_timestamp = backup_timestamp
                    # And go to the next backup
                    break


def backup_marker_path(folder: str) -> str:
    """Return the path to the backup marker file."""
    return os.path.join(folder, "backup.marker")


def find_backup_marker(folder: str, ssh_cmd: Optional[str]) -> Optional[str]:
    """Find the backup marker file in the given folder."""
    marker_path = backup_marker_path(folder)
    output = find(marker_path, ssh_cmd)
    return marker_path if output else None


def parse_ssh(
    src_folder: str,
    dest_folder: str,
    ssh_port: str,
    id_rsa: Optional[str],
) -> Tuple[str, str, str, str, str]:
    """Parse the source and destination folders for SSH usage."""
    ssh_src_folder_prefix = ""
    ssh_dest_folder_prefix = ""
    ssh_cmd = ""
    ssh_src_folder = ""
    ssh_dest_folder = ""

    if re.match(r"^[A-Za-z0-9\._%\+\-]+@[A-Za-z0-9.\-]+\:.+$", dest_folder):
        ssh_user, ssh_host, ssh_dest_folder = re.search(  # type: ignore[union-attr]
            r"^([A-Za-z0-9\._%\+\-]+)@([A-Za-z0-9.\-]+)\:(.+)$",
            dest_folder,
        ).groups()

        ssh_cmd = (
            f"ssh -p {ssh_port} -i {id_rsa} {ssh_user}@{ssh_host}"
            if id_rsa
            else f"ssh -p {ssh_port} {ssh_user}@{ssh_host}"
        )

        ssh_dest_folder_prefix = f"{ssh_user}@{ssh_host}:"

    if re.match(r"^[A-Za-z0-9\._%\+\-]+@[A-Za-z0-9.\-]+\:.+$", src_folder):
        ssh_user, ssh_host, ssh_src_folder = re.search(  # type: ignore[union-attr]
            r"^([A-Za-z0-9\._%\+\-]+)@([A-Za-z0-9.\-]+)\:(.+)$",
            src_folder,
        ).groups()

        ssh_cmd = (
            f"ssh -p {ssh_port} -i {id_rsa} {ssh_user}@{ssh_host}"
            if id_rsa
            else f"ssh -p {ssh_port} {ssh_user}@{ssh_host}"
        )

        ssh_src_folder_prefix = f"{ssh_user}@{ssh_host}:"

    return (
        ssh_src_folder_prefix,
        ssh_dest_folder_prefix,
        ssh_cmd,
        ssh_src_folder,
        ssh_dest_folder,
    )


class CmdResult(NamedTuple):
    stdout: str
    stderr: str
    returncode: int


def run_cmd(
    cmd: str,
    ssh_cmd: Optional[str] = None,
) -> CmdResult:
    """Run a command locally or remotely."""
    if ssh_cmd:
        print(f"Running remote command: [bold]{cmd}[/bold]")
        result = subprocess.run(
            f"{ssh_cmd} '{cmd}'",
            shell=True,
            capture_output=True,
            text=True,
        )
    else:
        print(f"Running local command: [bold]{cmd}[/bold]")
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
        )
    print(f"Command output: [bold]{result.stdout}[/bold]")
    return CmdResult(result.stdout.strip(), result.stderr.strip(), result.returncode)


def find(path: str, ssh_cmd: Optional[str]) -> str:
    """Find files in the given path, using the `find` command."""
    return run_cmd(f"find '{path}'", ssh_cmd).stdout


def get_absolute_path(path: str, ssh_cmd: Optional[str]) -> str:
    """Get the absolute path of the given path."""
    return run_cmd(f"cd '{path}';pwd", ssh_cmd).stdout


def mkdir(path: str, ssh_cmd: Optional[str]) -> None:
    """Create a directory."""
    run_cmd(f"mkdir -p -- '{path}'", ssh_cmd)


def rm_file(path: str, ssh_cmd: Optional[str]) -> None:
    """Remove a file."""
    run_cmd(f"rm -f -- '{path}'", ssh_cmd)


def rm_dir(path: str, ssh_cmd: Optional[str]) -> None:
    """Remove a directory."""
    run_cmd(f"rm -rf -- '{path}'", ssh_cmd)


def ln(src: str, dest: str, ssh_cmd: Optional[str]) -> None:
    """Create a symlink."""
    run_cmd(f"ln -s -- '{src}' '{dest}'", ssh_cmd)


def test_file_exists_src(path: str) -> bool:
    """Test if a file exists."""
    return run_cmd(f"test -e '{path}'", None).returncode == 0


def df_t_src(path: str) -> str:
    """Get the filesystem type of the given path."""
    return run_cmd(f"df -T '{path}'", None).stdout


def df_t(path: str, ssh_cmd: Optional[str]) -> str:
    """Get the filesystem type of the given path."""
    return run_cmd(f"df -T '{path}'", ssh_cmd).stdout


def check_dest_is_backup_folder(appname: str, dest_folder: str, ssh_cmd: str) -> None:
    """Check if the destination is a backup folder or drive."""
    marker_path = backup_marker_path(dest_folder)
    if not find_backup_marker(dest_folder, ssh_cmd):
        log_info(
            appname,
            "Safety check failed - the destination does not appear to be a backup folder or drive (marker file not found).",
        )
        log_info(
            appname,
            "If it is indeed a backup folder, you may add the marker file by running the following command:",
        )
        log_info_cmd(
            appname,
            f'mkdir -p -- "{dest_folder}" ; touch "{marker_path}"',
            ssh_cmd,
        )
        log_info(appname, "")
        sys.exit(1)


def get_link_dest_option(
    previous_dest: str,
    ssh_cmd: Optional[str],
    ssh_dest_folder_prefix: str,
    appname: str,
) -> str:
    """Get the --link-dest option for rsync."""
    link_dest_option = ""
    if not previous_dest:
        log_info(appname, "No previous backup - creating new one.")
    else:
        previous_dest = get_absolute_path(previous_dest, ssh_cmd)
        log_info(
            appname,
            f"Previous backup found - doing incremental backup from {ssh_dest_folder_prefix}{previous_dest}",
        )
        link_dest_option = f"--link-dest='{previous_dest}'"
    return link_dest_option


def handle_ssh(
    src_folder: str,
    dest_folder: str,
    ssh_port: str,
    id_rsa: str,
    appname: str,
    exclusion_file: str,
):
    """Handle SSH-related things for in the `main` function."""
    (
        ssh_src_folder_prefix,
        ssh_dest_folder_prefix,
        ssh_cmd,
        ssh_src_folder,
        ssh_dest_folder,
    ) = parse_ssh(src_folder, dest_folder, ssh_port, id_rsa)

    if ssh_dest_folder:
        dest_folder = ssh_dest_folder

    if ssh_src_folder:
        src_folder = ssh_src_folder

    dest_folder = dest_folder.rstrip("/")
    src_folder = src_folder.rstrip("/")

    if not src_folder or not dest_folder:
        log_error(appname, "Source and destination folder cannot be empty.")
        sys.exit(1)

    if (
        "'" in src_folder
        or "'" in dest_folder
        or (exclusion_file and "'" in exclusion_file)
    ):
        log_error(
            appname,
            "Source and destination directories may not contain single quote characters.",
        )
        sys.exit(1)
    return (
        src_folder,
        dest_folder,
        ssh_src_folder_prefix,
        ssh_dest_folder_prefix,
        ssh_cmd,
    )


def get_rsync_flags(
    src_folder: str,
    dest_folder: str,
    rsync_set_flags: str,
    rsync_append_flags: str,
    ssh_cmd: Optional[str],
    appname: str,
) -> List[str]:
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
        "fat" in df_t_src(src_folder).lower()
        or "fat" in df_t(dest_folder, ssh_cmd).lower()
    ):
        log_info(appname, "File-system is a version of FAT.")
        log_info(appname, "Using the --modify-window rsync parameter with value 2.")
        rsync_flags.append("--modify-window=2")

    if ssh_cmd:
        rsync_flags.append("--compress")
    return rsync_flags


def handle_still_running_or_failed_or_interrupted_backup(
    inprogress_file: str,
    mypid: int,
    dest: str,
    dest_folder: str,
    previous_dest: Optional[str],
    ssh_cmd: str,
    ssh_dest_folder_prefix: str,
    appname: str,
):
    """Handle cases when backup is still running or failed or interrupted backup."""
    if not find(inprogress_file, ssh_cmd):
        return
    # 1. Grab the PID of previous run from the PID file
    running_pid = run_cmd(f"cat {inprogress_file}", ssh_cmd).stdout

    if sys.platform == "cygwin":
        cmd = f"procps -wwfo cmd -p {running_pid} --no-headers | grep '{appname}'"
        running_cmd = run_cmd(cmd, ssh_cmd).stdout
        if running_cmd.returncode == 0:
            log_error(
                appname,
                f"Previous backup task is still active - aborting (command: {running_cmd.stdout}).",
            )
            sys.exit(1)
    else:
        ps_flags = "-axp" if sys.platform.startswith("netbsd") else "-p"
        cmd = f"ps -{ps_flags} {running_pid} -o 'command' | grep '{appname}'"
        if run_cmd(cmd).stdout:
            log_error(appname, "Previous backup task is still active - aborting.")
            sys.exit(1)

    if previous_dest:
        # - Last backup is moved to current backup folder so that it can be resumed.
        # - 2nd to last backup becomes last backup.
        log_info(
            appname,
            f"{ssh_dest_folder_prefix}{inprogress_file} already exists - the previous backup failed or was interrupted. Backup will resume from there.",
        )
        run_cmd(f"mv -- {previous_dest} {dest}", ssh_cmd)
        backups = find_backups(dest_folder, ssh_cmd)
        previous_dest = backups[1] if len(backups) > 1 else ""

        # Update PID to current process to avoid multiple concurrent resumes
        run_cmd(f"echo {mypid} > {inprogress_file}", ssh_cmd)


def deal_with_no_space_left(
    log_file,
    dest_folder,
    ssh_cmd,
    appname,
    auto_expire,
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
                appname,
                "No space left on device, and automatic purging of old backups is disabled.",
            )
            sys.exit(1)

        log_warn(
            appname,
            "No space left on device - removing oldest backup and resuming.",
        )
        backups = find_backups(dest_folder, ssh_cmd)
        if len(backups) < 2:
            log_error(appname, "No space left on device, and no old backup to delete.")
            sys.exit(1)

        expire_backup(sorted(backups)[-1], appname, ssh_cmd)
        return True
    return False


def check_rsync_errors(log_file, appname, auto_delete_log):
    """Check rsync errors."""
    with open(log_file) as f:
        log_data = f.read()
    if "rsync error:" in log_data:
        log_error(
            appname,
            f"Rsync reported an error. Run this command for more details: grep -E 'rsync:|rsync error:' '{log_file}'",
        )
    elif "rsync:" in log_data:
        log_warn(
            appname,
            f"Rsync reported a warning. Run this command for more details: grep -E 'rsync:|rsync error:' '{log_file}'",
        )
    else:
        log_info(appname, "Backup completed without errors.")
        if auto_delete_log:
            os.remove(log_file)


def start_backup(
    src_folder,
    dest,
    exclusion_file,
    inprogress_file,
    link_dest_option,
    rsync_flags,
    log_dir,
    mypid,
    ssh_cmd,
    ssh_port,
    ssh_src_folder_prefix,
    ssh_dest_folder_prefix,
    id_rsa,
    appname,
) -> str:
    """Start backup."""
    log_file = os.path.join(
        log_dir,
        f"{datetime.now().strftime('%Y-%m-%d-%H%M%S')}.log",
    )

    log_info(appname, "Starting backup...")
    log_info(appname, f"From: {ssh_src_folder_prefix}{src_folder}/")
    log_info(appname, f"To:   {ssh_dest_folder_prefix}{dest}/")

    cmd = "rsync"
    if ssh_cmd:
        if id_rsa:
            cmd = f"{cmd}  -e 'ssh -p {ssh_port} -i {id_rsa} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'"
        else:
            cmd = f"{cmd}  -e 'ssh -p {ssh_port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'"

    cmd = f"{cmd} {' '.join(rsync_flags)}"
    cmd = f"{cmd} --log-file '{log_file}'"
    if exclusion_file:
        cmd = f"{cmd} --exclude-from '{exclusion_file}'"

    cmd = f"{cmd} {link_dest_option}"
    cmd = f"{cmd} -- '{ssh_src_folder_prefix}{src_folder}/' '{ssh_dest_folder_prefix}{dest}/'"

    log_info(appname, "Running command:")
    log_info(appname, cmd)

    run_cmd(f"echo {mypid} > {inprogress_file}", ssh_cmd)

    subprocess.run(cmd, shell=True)
    return log_file


def main() -> None:
    """Main function."""
    # -----------------------------------------------------------------------------
    # Parse command-line arguments
    # -----------------------------------------------------------------------------
    args = parse_arguments()

    appname = "rsync-time-backup"
    signal.signal(signal.SIGINT, lambda n, f: terminate_script(appname, n, f))

    # -----------------------------------------------------------------------------
    # Set up variables
    # -----------------------------------------------------------------------------
    src_folder = args.src_folder
    dest_folder = args.dest_folder
    exclusion_file = args.exclusion_file
    log_dir = os.path.expandvars(os.path.expanduser(args.log_dir))
    auto_delete_log = True
    expiration_strategy = args.strategy
    auto_expire = not args.no_auto_expire
    ssh_port = args.port
    id_rsa = args.id_rsa

    # -----------------------------------------------------------------------------
    # SSH handling
    # -----------------------------------------------------------------------------
    (
        src_folder,
        dest_folder,
        ssh_src_folder_prefix,
        ssh_dest_folder_prefix,
        ssh_cmd,
    ) = handle_ssh(src_folder, dest_folder, ssh_port, id_rsa, appname, exclusion_file)

    # -----------------------------------------------------------------------------
    # Check if source folder exists
    # -----------------------------------------------------------------------------
    if not test_file_exists_src(src_folder):
        log_error(appname, f"Source folder '{src_folder}' does not exist - aborting.")
        sys.exit(1)

    # -----------------------------------------------------------------------------
    # Check if destination is a backup folder
    # -----------------------------------------------------------------------------
    check_dest_is_backup_folder(appname, dest_folder, ssh_cmd)

    # -----------------------------------------------------------------------------
    # Set up more variables
    # -----------------------------------------------------------------------------
    now = datetime.now().strftime("%Y-%m-%d-%H%M%S")

    dest = os.path.join(dest_folder, now)
    _backups = sorted(find_backups(dest_folder, ssh_cmd), reverse=True)
    previous_dest = _backups[0] if _backups else None
    inprogress_file = os.path.join(dest_folder, "backup.inprogress")
    mypid = os.getpid()

    # -----------------------------------------------------------------------------
    # Create log folder if it doesn't exist
    # -----------------------------------------------------------------------------
    if not os.path.exists(log_dir):
        log_info(appname, f"Creating log folder in '{log_dir}'...")
        os.makedirs(log_dir)

    # -----------------------------------------------------------------------------
    # Handle case where a previous backup failed or was interrupted
    # -----------------------------------------------------------------------------
    handle_still_running_or_failed_or_interrupted_backup(
        inprogress_file,
        mypid,
        dest,
        dest_folder,
        previous_dest,
        ssh_cmd,
        ssh_dest_folder_prefix,
        appname,
    )

    # -----------------------------------------------------------------------------
    # Set rsync flags
    # -----------------------------------------------------------------------------
    rsync_flags = get_rsync_flags(
        src_folder,
        dest_folder,
        args.rsync_set_flags,
        args.rsync_append_flags,
        ssh_cmd,
        appname,
    )

    for _ in range(10):  # max 10 retries when no space left
        # -----------------------------------------------------------------------------
        # Incremental backup handling
        # -----------------------------------------------------------------------------
        link_dest_option = get_link_dest_option(previous_dest)
        # -----------------------------------------------------------------------------
        # Create destination folder if it doesn't already exist
        # -----------------------------------------------------------------------------
        if not find(dest, ssh_cmd):
            log_info(appname, f"Creating destination {ssh_dest_folder_prefix}{dest}")
            mkdir(dest, ssh_cmd)

        # -----------------------------------------------------------------------------
        # Purge certain old backups before beginning new backup
        # -----------------------------------------------------------------------------
        if previous_dest:
            expire_backups(
                dest_folder,
                appname,
                expiration_strategy,
                previous_dest,
                ssh_cmd,
            )
        else:
            expire_backups(dest_folder, appname, expiration_strategy, dest, ssh_cmd)

        # -----------------------------------------------------------------------------
        # Start backup
        # -----------------------------------------------------------------------------
        log_file = start_backup(
            src_folder,
            dest,
            exclusion_file,
            inprogress_file,
            link_dest_option,
            rsync_flags,
            log_dir,
            mypid,
            ssh_cmd,
            ssh_port,
            ssh_src_folder_prefix,
            ssh_dest_folder_prefix,
            id_rsa,
            appname,
        )
        # -----------------------------------------------------------------------------
        # Check for errors
        # -----------------------------------------------------------------------------
        retry = deal_with_no_space_left(
            log_file,
            dest_folder,
            ssh_cmd,
            appname,
            auto_expire,
        )
        if not retry:
            break

    # -----------------------------------------------------------------------------
    # Check whether rsync reported any errors
    # -----------------------------------------------------------------------------
    check_rsync_errors(log_file, appname, auto_delete_log)

    # -----------------------------------------------------------------------------
    # Add symlink to last backup
    # -----------------------------------------------------------------------------
    rm_file(os.path.join(dest_folder, "latest"), ssh_cmd)
    ln(
        os.path.basename(dest),
        os.path.join(dest_folder, "latest"),
        ssh_cmd,
    )

    rm_file(inprogress_file, ssh_cmd)


if __name__ == "__main__":
    main()
