<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Rsync Time Machine 🕰️💾](#rsync-time-machine-)
  - [Features 🌟](#features-)
  - [Usage 📚](#usage-)
  - [Installation 🛠️](#installation-)
  - [Examples 💡](#examples-)
  - [Backup Expiration Logic 🗓️](#backup-expiration-logic-)
  - [Exclusion File 📄](#exclusion-file-)
  - [Built-in Lock 🔒](#built-in-lock-)
  - [Rsync Options ⚙️](#rsync-options-)
  - [No Automatic Backup Expiration 🚫](#no-automatic-backup-expiration-)
  - [How to Restore 🔄](#how-to-restore-)
  - [Support and Contributions ❤️](#support-and-contributions-)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Rsync Time Machine 🕰️💾

Introducing `rsync-time-machine.py` - a Python port of the `rsync-time-backup` script, offering Time Machine-style backups using rsync. It creates incremental backups of files and directories to the destination of your choice. The backups are structured in a way that makes it easy to recover any file at any point in time. 🚀

It works on Linux, macOS, and Windows (via WSL or Cygwin). The main advantage over Time Machine is flexibility, as it can backup from/to any filesystem and works on any platform. You can also backup to a Truecrypt drive without any problem. 😃

`rsync-time-machine.py` is fully tested, has no external dependencies, is fully compatible with `rsync-time-backup`, offers pretty terminal output, and is fully typed! 🎉

## Features 🌟

* 📁 Each backup is in its own folder named after the current timestamp.
* 🔒 Backup to/from remote destinations over SSH.
* 🔗 Files that haven't changed from one backup to the next are hard-linked to the previous backup, saving space.
* ⚠️ Safety check - the backup will only happen if the destination has explicitly been marked as a backup destination.
* 🔄 Resume feature - if a backup has failed or was interrupted, the tool will resume from there on the next backup.
* 🚫 Exclude file - support for pattern-based exclusion via the `--exclude-from` rsync parameter.
* 🧹 Automatically purge old backups based on a configurable expiration strategy.
* 🔗 "latest" symlink that points to the latest successful backup.

## Usage 📚

To use `rsync-time-machine.py`, you'll need to provide source and destination paths, along with any desired options:

```bash
rsync-time-machine --help
```
Shows the help message:

<!-- CODE:START:BASH -->
<!-- echo '```bash' -->
<!-- rsync-time-machine --help -->
<!-- echo '```' -->
<!-- CODE:END -->

<!-- OUTPUT:START -->
<!-- OUTPUT:END -->

Please refer to the original `rsync-time-backup` README for a list of options, as they have been preserved in the Python port.

## Installation 🛠️

To install `rsync-time-machine.py`, simply clone the repository:

```
git clone https://github.com/basnijholt/rsync-time-machine.py
```

## Examples 💡

* Backup the home folder to backup_drive:

```
python rsync-time-machine.py /home /mnt/backup_drive
```

* Backup with exclusion list:

```
python rsync-time-machine.py /home /mnt/backup_drive excluded_patterns.txt
```

For more examples and detailed usage instructions, please refer to the original `rsync-time-backup` README.

## Backup Expiration Logic 🗓️

Backup sets are automatically deleted following a simple expiration strategy defined with the `--strategy` flag. The default strategy is `1:1 30:7 365:30`. Please see the original README for a detailed explanation.

## Exclusion File 📄

An optional exclude file can be provided as a third parameter, compatible with the `--exclude-from` parameter of rsync.

## Built-in Lock 🔒

The script is designed so that only one backup operation can be active for a given directory, avoiding conflicts.

## Rsync Options ⚙️

To display, add, or remove rsync options, use the `--rsync-get-flags`, `--rsync-append-flags`, or `--rsync-set-flags` options.

## No Automatic Backup Expiration 🚫

Use the `--no-auto-expire` flag to disable the default behavior of purging old backups when out of space.

## How to Restore 🔄

Restoring files from the backup is simple, as the script creates a backup in a regular directory. You can easily copy the files back to the original directory using a command like:

```
rsync -aP /path/to/last/backup/ /path/to/restore/to/
```

Consider using the `--dry-run` option to check what exactly is going to be copied. If you want to delete files that exist in the destination but not in the backup, use the `--delete` option. Be extra cautious when using this option to avoid data loss.

You can also restore files using any file explorer, including Finder on macOS or the command line.

## Support and Contributions ❤️

We appreciate your feedback and contributions! If you encounter any issues or have suggestions for improvements, please file an issue on the GitHub repository. We also welcome pull requests for bug fixes or new features.

Happy backing up! 💾🕰️🎉
