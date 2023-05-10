import argparse
from typing import List, Optional, Tuple
import os
import argparse

import re
from typing import Tuple
import os
import subprocess
from datetime import datetime
import signal
import sys
import shutil

# -----------------------------------------------------------------------------
# Log functions
# -----------------------------------------------------------------------------


def log_info(appname: str, message: str) -> None:
    print(f"{appname}: {message}")


def log_warn(appname: str, message: str) -> None:
    print(f"{appname}: [WARNING] {message}", file=sys.stderr)


def log_error(appname: str, message: str) -> None:
    print(f"{appname}: [ERROR] {message}", file=sys.stderr)


def log_info_cmd(
    appname: str, message: str, ssh_dest_folder_prefix: str, ssh_cmd: str
) -> None:
    if ssh_dest_folder_prefix:
        print(f"{appname}: {ssh_cmd} '{message}'")
    else:
        print(f"{appname}: {message}")


# -----------------------------------------------------------------------------
# Make sure everything really stops when CTRL+C is pressed
# -----------------------------------------------------------------------------


def terminate_script(appname: str, signal_number: int, frame) -> None:
    log_info(appname, "SIGINT caught.")
    sys.exit(1)


# -----------------------------------------------------------------------------
# Small utility functions for reducing code duplication
# -----------------------------------------------------------------------------


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments and return the parsed arguments.
    (Replaces argument parsing part in the Bash script)
    """
    parser = argparse.ArgumentParser(
        description="A script for creating and managing time-stamped backups using rsync."
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
        "src_folder", help="Source folder for backup. Format: [USER@HOST:]SOURCE"
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


def expire_backup(backup_path: str, appname: str, find_backup_marker: callable) -> None:
    """
    Expire the given backup folder after checking if it's on a backup destination.
    """
    parent_dir = os.path.dirname(backup_path)

    # Double-check that we're on a backup destination to be completely
    # sure we're deleting the right folder
    if not find_backup_marker(parent_dir):
        log_error(appname, f"{backup_path} is not on a backup destination - aborting.")
        sys.exit(1)

    log_info(appname, f"Expiring {backup_path}")
    shutil.rmtree(backup_path)


def expire_backups(
    appname: str,
    find_backups: callable,
    parse_date: callable,
    expiration_strategy: str,
    backup_to_keep: str,
) -> None:
    current_timestamp = int(datetime.now().timestamp())
    last_kept_timestamp = 9999999999

    # We will also keep the oldest backup
    oldest_backup_to_keep = sorted(find_backups())[0]

    # Process each backup dir from the oldest to the most recent
    for backup_dir in sorted(find_backups()):
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
                    expire_backup(backup_dir, appname, find_backup_marker)
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
                    expire_backup(backup_dir, appname, find_backup_marker)
                    # Backup deleted, no point to check shorter timespan strategies - go to the next backup
                    break

                else:
                    # No: Keep it.
                    # This is now the last kept backup
                    last_kept_timestamp = backup_timestamp
                    # And go to the next backup
                    break


def backup_marker_path(folder: str) -> str:
    return os.path.join(folder, "backup.marker")


def find_backup_marker(folder: str) -> Optional[str]:
    marker_path = backup_marker_path(folder)
    return marker_path if os.path.exists(marker_path) else None


def parse_ssh(
    src_folder: str, dest_folder: str, ssh_port: str, id_rsa: Optional[str]
) -> Tuple[str, str, str, str]:
    ssh_src_folder_prefix = ""
    ssh_dest_folder_prefix = ""
    ssh_cmd = ""

    if re.match(r"^[A-Za-z0-9\._%\+\-]+@[A-Za-z0-9.\-]+\:.+$", dest_folder):
        ssh_user, ssh_host, ssh_dest_folder = re.search(
            r"^([A-Za-z0-9\._%\+\-]+)@([A-Za-z0-9.\-]+)\:(.+)$", dest_folder
        ).groups()

        if id_rsa:
            ssh_cmd = f"ssh -p {ssh_port} -i {id_rsa} {ssh_user}@{ssh_host}"
        else:
            ssh_cmd = f"ssh -p {ssh_port} {ssh_user}@{ssh_host}"

        ssh_dest_folder_prefix = f"{ssh_user}@{ssh_host}:"

    if re.match(r"^[A-Za-z0-9\._%\+\-]+@[A-Za-z0-9.\-]+\:.+$", src_folder):
        ssh_user, ssh_host, ssh_src_folder = re.search(
            r"^([A-Za-z0-9\._%\+\-]+)@([A-Za-z0-9.\-]+)\:(.+)$", src_folder
        ).groups()

        if id_rsa:
            ssh_cmd = f"ssh -p {ssh_port} -i {id_rsa} {ssh_user}@{ssh_host}"
        else:
            ssh_cmd = f"ssh -p {ssh_port} {ssh_user}@{ssh_host}"

        ssh_src_folder_prefix = f"{ssh_user}@{ssh_host}:"

    return ssh_src_folder_prefix, ssh_dest_folder_prefix, ssh_cmd, ssh_dest_folder


def run_cmd(cmd: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]) -> None:
    if ssh_folder_prefix:
        subprocess.run(f"{ssh_cmd} '{cmd}'", shell=True)
    else:
        subprocess.run(cmd, shell=True)


def find(path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]) -> str:
    return run_cmd(f"find '{path}'", ssh_cmd, ssh_folder_prefix)


def get_absolute_path(
    path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]
) -> str:
    return run_cmd(f"cd '{path}';pwd", ssh_cmd, ssh_folder_prefix)


def mkdir(path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]) -> None:
    run_cmd(f"mkdir -p -- '{path}'", ssh_cmd, ssh_folder_prefix)


def rm_file(
    path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]
) -> None:
    run_cmd(f"rm -f -- '{path}'", ssh_cmd, ssh_folder_prefix)


def rm_dir(path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]) -> None:
    run_cmd(f"rm -rf -- '{path}'", ssh_cmd, ssh_folder_prefix)


def touch(path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]) -> None:
    run_cmd(f"touch -- '{path}'", ssh_cmd, ssh_folder_prefix)


def ln(
    src: str, dest: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]
) -> None:
    run_cmd(f"ln -s -- '{src}' '{dest}'", ssh_cmd, ssh_folder_prefix)


def test_file_exists_src(
    path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]
) -> None:
    run_cmd(f"test -e '{path}'", ssh_cmd, ssh_folder_prefix)


def df_t_src(
    path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]
) -> None:
    run_cmd(f"df -T '{path}'", ssh_cmd, ssh_folder_prefix)


def df_t(path: str, ssh_cmd: Optional[str], ssh_folder_prefix: Optional[str]) -> None:
    run_cmd(f"df -T '{path}'", ssh_cmd, ssh_folder_prefix)
