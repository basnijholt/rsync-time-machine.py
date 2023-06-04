# Rsync Time Machine 🕰️💾

![Build](https://github.com/basnijholt/rsync-time-machine.py/actions/workflows/pytest.yml/badge.svg)
[![Coverage](https://img.shields.io/codecov/c/github/basnijholt/rsync-time-machine.py)](https://codecov.io/gh/basnijholt/rsync-time-machine.py)
[![GitHub](https://img.shields.io/github/stars/basnijholt/rsync-time-machine.py.svg?style=social)](https://github.com/basnijholt/rsync-time-machine.py/stargazers)
[![PyPI](https://img.shields.io/pypi/v/rsync-time-machine.svg)](https://pypi.python.org/pypi/rsync-time-machine)
[![License](https://img.shields.io/github/license/basnijholt/rsync-time-machine.py)](https://github.com/basnijholt/rsync-time-machine.py/blob/main/LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/rsync-time-machine)](https://pypi.python.org/pypi/rsync-time-machine)
![Open Issues](https://img.shields.io/github/issues-raw/basnijholt/rsync-time-machine.py)

Introducing `rsync-time-machine.py` - a Python port of the [`rsync-time-backup`](https://github.com/laurent22/rsync-time-backup) script, offering Time Machine-style backups using rsync. It creates incremental backups of files and directories to the destination of your choice. The backups are structured in a way that makes it easy to recover any file at any point in time. 🚀

It works on Linux, macOS, and Windows (via WSL or Cygwin). The main advantage over Time Machine is flexibility, as it can backup from/to any filesystem and works on any platform. You can also backup to a Truecrypt drive without any problem. 😃

`rsync-time-machine.py` is fully tested, has no external dependencies (only Python ≥3.7 🐍), is fully compatible with [`rsync-time-backup`](https://github.com/laurent22/rsync-time-backup), offers pretty terminal output, and is fully typed! 🎉

<details><summary><b><u>[ToC]</u></b> 📚</summary>

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [:star2: Features](#star2-features)
- [:books: Usage](#books-usage)
- [:hammer_and_wrench: Installation](#hammer_and_wrench-installation)
- [:bulb: Examples](#bulb-examples)
- [:calendar: Backup Expiration Logic](#calendar-backup-expiration-logic)
- [:page_facing_up: Exclusion File](#page_facing_up-exclusion-file)
- [:lock: Built-in Lock](#lock-built-in-lock)
- [:gear: Rsync Options](#gear-rsync-options)
- [:no_entry_sign: No Automatic Backup Expiration](#no_entry_sign-no-automatic-backup-expiration)
- [:arrows_counterclockwise: How to Restore](#arrows_counterclockwise-how-to-restore)
- [:star: Featured on](#star-featured-on)
- [:heart: Support and Contributions](#heart-support-and-contributions)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

</details>

## :star2: Features

* 📁 Each backup is in its own folder named after the current timestamp.
* 🔒 Backup to/from remote destinations over SSH.
* 🔗 Files that haven't changed from one backup to the next are hard-linked to the previous backup, saving space.
* ⚠️ Safety check - the backup will only happen if the destination has explicitly been marked as a backup destination.
* 🔄 Resume feature - if a backup has failed or was interrupted, the tool will resume from there on the next backup.
* 🚫 Exclude file - support for pattern-based exclusion via the `--exclude-from` rsync parameter.
* 🧹 Automatically purge old backups based on a configurable expiration strategy.
* 🔗 "latest" symlink that points to the latest successful backup.

## :books: Usage

To use `rsync-time-machine.py`, you'll need to provide source and destination paths, along with any desired options:

```bash
rsync-time-machine --help
```
Shows the help message:

<!-- CODE:BASH:START -->
<!-- echo '```bash' -->
<!-- rsync-time-machine --help -->
<!-- echo '```' -->
<!-- CODE:END -->

<!-- OUTPUT:START -->
<!-- ⚠️ This content is auto-generated by `markdown-code-runner`. -->
```bash
usage: rsync-time-machine [-h] [-p PORT] [-i ID_RSA] [--rsync-get-flags]
                          [--rsync-set-flags RSYNC_SET_FLAGS]
                          [--rsync-append-flags RSYNC_APPEND_FLAGS]
                          [--log-dir LOG_DIR] [--strategy STRATEGY]
                          [--no-auto-expire] [--allow-host-only]
                          [--exclude-from EXCLUDE_FROM] [-v]
                          src_folder dest_folder [exclusion_file]

A script for creating and managing time-stamped backups using rsync.

positional arguments:
  src_folder            Source folder for backup. Format: [USER@HOST:]SOURCE
  dest_folder           Destination folder for backup. Format:
                        [USER@HOST:]DESTINATION
  exclusion_file        Path to the file containing exclude patterns. Cannot
                        be used together with --exclude-from.

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  SSH port.
  -i ID_RSA, --id_rsa ID_RSA
                        Specify the private ssh key to use.
  --rsync-get-flags     Display the default rsync flags that are used for
                        backup. If using remote drive over SSH, --compress
                        will be added.
  --rsync-set-flags RSYNC_SET_FLAGS
                        Set the rsync flags that are going to be used for
                        backup.
  --rsync-append-flags RSYNC_APPEND_FLAGS
                        Append the rsync flags that are going to be used for
                        backup.
  --log-dir LOG_DIR     Set the log file directory. If this flag is set,
                        generated files will not be managed by the script - in
                        particular they will not be automatically deleted.
                        Default: $HOME/.rsync-time-backup
  --strategy STRATEGY   Set the expiration strategy. Default: "1:1 30:7
                        365:30" means after one day, keep one backup per day.
                        After 30 days, keep one backup every 7 days. After 365
                        days keep one backup every 30 days.
  --no-auto-expire      Disable automatically deleting backups when out of
                        space. Instead, an error is logged, and the backup is
                        aborted.
  --allow-host-only     By default, the script expects a 'USER@HOST' pattern
                        for specifying SSH connections. When this flag is
                        used, it allows for the 'HOST' pattern without a
                        specified user. This is useful if you want to use
                        configurations from the `.ssh/config` file or rely on
                        the current username. Note: this option will not
                        enforce SSH usage, it only broadens the accepted input
                        formats.
  --exclude-from EXCLUDE_FROM
                        Path to the file containing exclude patterns.
                        Alternative to the positional `exclusion_file`. Not to
                        be used with `exclusion_file`.
  -v, --verbose         Enable verbose output. This will slow down the backup
                        process (in simple tests by 2x).
```

<!-- OUTPUT:END -->

Please refer to the original [`rsync-time-backup`](https://github.com/laurent22/rsync-time-backup) README for a list of options, as they have been preserved in the Python port.

## :hammer_and_wrench: Installation

To install `rsync-time-machine.py`, simply clone the repository:

```bash
pip install rsync-time-machine
```

and use it like `rsync-time-machine --help`

Or just copy the script to your computer:

```bash
wget https://raw.githubusercontent.com/basnijholt/rsync-time-machine.py/main/rsync_time_machine.py
```
and use it like `./rsync_time_machine.py --help`

## :bulb: Examples

* Backup the home folder to backup_drive:

```
./rsync_time_machine.py /home /mnt/backup_drive
```

* Backup with exclusion list:

```
./rsync_time_machine.py /home /mnt/backup_drive excluded_patterns.txt
```

For more examples and detailed usage instructions, please refer to the original [`rsync-time-backup`](https://github.com/laurent22/rsync-time-backup) README.

## :calendar: Backup Expiration Logic

Backup sets are automatically deleted following a simple expiration strategy defined with the `--strategy` flag. The default strategy is `1:1 30:7 365:30`. Please see the original README for a detailed explanation.

## :page_facing_up: Exclusion File

An optional exclude file can be provided as a third parameter, compatible with the `--exclude-from` parameter of rsync.

The `--exclude-from` option in `rsync-time-machine.py` allows you to exclude specific files or directories from the backup process. You can provide an exclusion file containing patterns for files or directories that should be excluded.

<details>
<summary>📖🔽 Click here to expand the docs on <code>--exclude-from</code> 🔽📖</summary>

Here's how to use the `--exclude-from` feature in `rsync-time-machine.py`:

1. Create a text file named `exclusion_file.txt` (or any other name you prefer) in your preferred location.
2. Add the exclusion patterns to the file, one pattern per line. Patterns can be literal strings, wildcards, or character ranges.
3. Save the file.

To use this exclusion file while performing a backup with `rsync-time-machine.py`, include it as the third positional argument in your command (or with `--exclude-from exclusion_file.txt`). For example:

```bash
rsync-time-machine.py /home /mnt/backup_drive exclusion_file.txt
```

In this example, `/home` is the source folder, `/mnt/backup_drive` is the destination folder, and `exclusion_file.txt` contains the exclude patterns.

Here's a sample `exclusion_file.txt`:

```
+ /home/.fileA
- /home/.*
- /home/junk/
```

In this example:

- `+ /home/.fileA`: Include the file `.fileA` from the `home` directory.
- `- /home/.*`: Exclude all hidden files (files starting with a dot) from the `home` directory.
- `- /home/junk/`: Exclude the entire `junk` directory from the `home` directory.

Remember that the order of patterns matters, as rsync reads the file top-down and acts on the first matching pattern it encounters.

See [this tutorial](https://web.archive.org/web/20230126121643/https://sites.google.com/site/rsync2u/home/rsync-tutorial/the-exclude-from-option) for more information.

</details>

## :lock: Built-in Lock

The script is designed so that only one backup operation can be active for a given directory, avoiding conflicts.

## :gear: Rsync Options

To display, add, or remove rsync options, use the `--rsync-get-flags`, `--rsync-append-flags`, or `--rsync-set-flags` options.

## :no_entry_sign: No Automatic Backup Expiration

Use the `--no-auto-expire` flag to disable the default behavior of purging old backups when out of space.

## :arrows_counterclockwise: How to Restore

Restoring files from the backup is simple, as the script creates a backup in a regular directory. You can easily copy the files back to the original directory using a command like:

```
rsync -aP /path/to/last/backup/ /path/to/restore/to/
```

Consider using the `--dry-run` option to check what exactly is going to be copied. If you want to delete files that exist in the destination but not in the backup, use the `--delete` option. Be extra cautious when using this option to avoid data loss.

You can also restore files using any file explorer, including Finder on macOS or the command line.

## :star: Featured on

- the Real Python podcast: [Episode 158: Building Python CI With Docker & Applying for a Hacker Initiative Grant @ 00:26:28](https://realpython.com/podcasts/rpp/158/#t=1588)

## :heart: Support and Contributions

We appreciate your feedback and contributions! If you encounter any issues or have suggestions for improvements, please file an issue on the GitHub repository. We also welcome pull requests for bug fixes or new features.

Happy backing up! 💾🕰️🎉
