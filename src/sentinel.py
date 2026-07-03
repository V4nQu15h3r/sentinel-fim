#!/usr/bin/env python3
"""
SentinelFIM - A File Integrity Monitor with Self-Healing and Quarantine.

WHAT THIS TOOL DOES (in plain English):
  1. "init"    -> Takes a snapshot ("baseline") of a folder: it records a
                  unique fingerprint (hash) of every file, and keeps a safe
                  copy of every file in a hidden ".backup" folder.
  2. "monitor" -> Repeatedly re-checks the folder against that snapshot:
                    - If a known file was deleted or changed -> it is
                      automatically restored from the backup copy
                      (MODIFIED / DELETED -> Self-Healing).
                    - If a brand-new, unrecognized file shows up -> it is
                      moved into a ".quarantine" folder and made read-only
                      so it can't be executed or edited
                      (CREATED / unauthorized -> Quarantine).

No third-party libraries are used - only Python's built-in ("standard")
library, so this runs the same way on Windows, macOS, and Linux.
"""

# ---------------------------------------------------------------------------
# IMPORTS - all from Python's standard library (nothing to "pip install")
# ---------------------------------------------------------------------------
import os          # lets us change file permissions (e.g. make a file read-only)
import stat         # gives us readable names for permission bits (e.g. "read-only")
import sys          # lets us exit the program and read command-line behavior
import json         # reads/writes our baseline data as a .json file
import time         # lets us timestamp logs and pause between monitoring checks
import shutil       # high-level file copy/move operations (cross-platform safe)
import hashlib      # calculates SHA-256 fingerprints ("hashes") of file content
import argparse     # parses command-line arguments like `--path` and `--interval`
from pathlib import Path   # the modern, cross-platform way to work with file paths
from datetime import datetime  # for human-readable timestamps in logs


# ---------------------------------------------------------------------------
# CONFIGURATION - names of the hidden folders/files SentinelFIM creates
# ---------------------------------------------------------------------------
BASELINE_NAME = ".baseline.json"     # stores the "known good" fingerprint of every file
BACKUP_DIR_NAME = ".backup"          # stores a safe copy of every known-good file
QUARANTINE_DIR_NAME = ".quarantine"  # holds suspicious/unauthorized files we isolate

# How many bytes we read into memory at a time while hashing. Keeping this
# small (4096 bytes = 4KB) means a 10GB file is hashed piece-by-piece
# instead of being loaded into RAM all at once, so the tool can't crash
# from running out of memory on huge files.
HASH_CHUNK_SIZE = 4096

# These are SentinelFIM's own housekeeping items. We must never treat them
# as "monitored" files, or the tool would try to quarantine its own backups!
RESERVED_NAMES = {BASELINE_NAME, BACKUP_DIR_NAME, QUARANTINE_DIR_NAME}


# ---------------------------------------------------------------------------
# TERMINAL COLORS - purely cosmetic, makes the log output easy to scan
# ---------------------------------------------------------------------------
class Colors:
    """ANSI escape codes that color terminal text. If your terminal doesn't
    support colors, these are simply ignored on most modern terminals."""
    RESET = "\033[0m"
    GRAY = "\033[90m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"


def _enable_windows_ansi_support():
    """Older Windows terminals (cmd.exe) don't render ANSI colors unless a
    special mode is switched on. This one line safely turns that mode on.
    On macOS/Linux this does nothing and is harmless."""
    if os.name == "nt":
        os.system("")


def log(message: str, level: str = "INFO"):
    """Prints a single, timestamped, color-coded log line in a consistent
    format, e.g.:
        [2026-07-04 10:15:02] [RESTORED] index.html
    """
    colors_by_level = {
        "INFO": Colors.CYAN,
        "OK": Colors.GREEN,
        "WARN": Colors.YELLOW,
        "ERROR": Colors.RED,
        "RESTORED": Colors.GREEN,
        "QUARANTINED": Colors.MAGENTA,
    }
    color = colors_by_level.get(level, Colors.RESET)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} "
          f"{color}{Colors.BOLD}[{level}]{Colors.RESET} {message}")


# ---------------------------------------------------------------------------
# CORE HELPERS
# ---------------------------------------------------------------------------
def hash_file(file_path: Path, chunk_size: int = HASH_CHUNK_SIZE) -> str:
    """Calculates the SHA-256 hash (a unique 'fingerprint') of a file's
    contents. If even a single byte of the file changes, this fingerprint
    changes completely - that's how we detect modifications.

    We read the file in small 4096-byte chunks instead of loading the
    whole file into memory at once. This is what allows SentinelFIM to
    safely hash very large files (e.g. multi-gigabyte logs) without
    running out of memory.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


def discover_files(target_dir: Path):
    """Walks through every file inside target_dir (including subfolders)
    and yields each one, EXCLUDING SentinelFIM's own hidden housekeeping
    folders (.backup, .quarantine, .baseline.json).
    """
    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue  # skip folders, we only care about files
        relative_parts = path.relative_to(target_dir).parts
        if relative_parts and relative_parts[0] in RESERVED_NAMES:
            continue
        yield path


def make_read_only(file_path: Path):
    """Strips write and execute permissions from a file, cross-platform.

    On Windows, 'chmod' only really controls the read-only flag - Windows
    doesn't use Unix-style execute permissions, so a read-only file is
    effectively the safest state there.

    On macOS/Linux, we explicitly set permissions to read-only for the
    owner/group/others (0o444), which also removes execute permission.
    """
    try:
        os.chmod(file_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except Exception as e:
        log(f"Could not fully lock down permissions on {file_path.name}: {e}", "WARN")


# ---------------------------------------------------------------------------
# COMMAND: init
# ---------------------------------------------------------------------------
def cmd_init(target_dir: Path):
    """Builds the baseline snapshot:
      1. Hashes every file in target_dir.
      2. Saves those hashes to .baseline.json.
      3. Copies every file into .backup/ (mirroring the folder structure),
         so that "self-healing" has something to restore from later.
    """
    if not target_dir.is_dir():
        log(f"'{target_dir}' is not a valid directory.", "ERROR")
        sys.exit(1)

    backup_dir = target_dir / BACKUP_DIR_NAME
    quarantine_dir = target_dir / QUARANTINE_DIR_NAME

    # Start fresh: if a backup already exists from a previous init, replace it.
    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    baseline = {}
    file_count = 0

    for file_path in discover_files(target_dir):
        # relative_path is the file's location *relative to* target_dir,
        # e.g. "subfolder/index.html". Stored with forward slashes
        # (as_posix) so the baseline file looks identical whether it was
        # created on Windows or macOS/Linux.
        relative_path = file_path.relative_to(target_dir).as_posix()

        file_hash = hash_file(file_path)
        baseline[relative_path] = file_hash

        # Copy the file into .backup/, preserving its subfolder structure.
        backup_target = backup_dir / relative_path
        backup_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, backup_target)  # copy2 preserves metadata too

        file_count += 1
        log(f"Baselined: {relative_path}", "OK")

    baseline_data = {
        "created_at": datetime.now().isoformat(),
        "target_dir": str(target_dir),
        "files": baseline,
    }
    baseline_path = target_dir / BASELINE_NAME
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)

    log(f"Baseline created with {file_count} file(s) -> {baseline_path}", "OK")
    log(f"Backups stored in -> {backup_dir}", "OK")


# ---------------------------------------------------------------------------
# COMMAND: monitor
# ---------------------------------------------------------------------------
def load_baseline(target_dir: Path) -> dict:
    """Loads the .baseline.json file created by `init`. Exits with a clear
    error message if it doesn't exist yet."""
    baseline_path = target_dir / BASELINE_NAME
    if not baseline_path.exists():
        log(f"No baseline found in '{target_dir}'. Run 'init' first.", "ERROR")
        sys.exit(1)
    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("files", {})


def restore_file(target_dir: Path, backup_dir: Path, relative_path: str, reason: str):
    """Copies a file back from .backup/ to its original location, overwriting
    whatever (if anything) is currently there. This is the 'self-healing'
    action, used for both DELETED and MODIFIED files."""
    backup_source = backup_dir / relative_path
    restore_destination = target_dir / relative_path

    if not backup_source.exists():
        log(f"Cannot restore '{relative_path}' - no backup copy exists!", "ERROR")
        return

    restore_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup_source, restore_destination)
    log(f"{relative_path}  (reason: {reason})", "RESTORED")


def quarantine_file(target_dir: Path, quarantine_dir: Path, file_path: Path):
    """Moves an unrecognized (CREATED / unauthorized) file into
    .quarantine/ and strips its permissions so it can't be run or edited."""
    relative_path = file_path.relative_to(target_dir).as_posix()
    destination = quarantine_dir / relative_path

    # Avoid collisions if a file with the same name was quarantined before.
    if destination.exists():
        timestamp_suffix = datetime.now().strftime("%Y%m%d%H%M%S")
        destination = destination.with_name(f"{timestamp_suffix}_{destination.name}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(file_path), str(destination))
    make_read_only(destination)
    log(f"{relative_path}  -> moved to {QUARANTINE_DIR_NAME}/ and locked read-only", "QUARANTINED")


def cmd_monitor(target_dir: Path, interval: int):
    """The main monitoring loop. Every `interval` seconds, it:
      1. Re-scans target_dir for its current files.
      2. Compares that against the baseline.
      3. Restores anything missing/modified, quarantines anything new.
    Press Ctrl+C to stop monitoring.
    """
    baseline = load_baseline(target_dir)
    backup_dir = target_dir / BACKUP_DIR_NAME
    quarantine_dir = target_dir / QUARANTINE_DIR_NAME
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    if not backup_dir.exists():
        log("No .backup folder found - self-healing (restore) will not be "
            "possible until you re-run 'init'.", "WARN")

    log(f"Monitoring '{target_dir}' every {interval} second(s). "
        f"Press Ctrl+C to stop.", "INFO")

    try:
        while True:
            current_files = {}
            for file_path in discover_files(target_dir):
                relative_path = file_path.relative_to(target_dir).as_posix()
                current_files[relative_path] = file_path

            baseline_paths = set(baseline.keys())
            current_paths = set(current_files.keys())

            # --- DELETED: in baseline, but missing on disk -> Self-Heal ---
            deleted_paths = baseline_paths - current_paths
            for relative_path in sorted(deleted_paths):
                restore_file(target_dir, backup_dir, relative_path, "file was deleted")

            # --- MODIFIED: in both, but hash differs -> Self-Heal ---
            common_paths = baseline_paths & current_paths
            modified_paths = set()
            for relative_path in sorted(common_paths):
                current_hash = hash_file(current_files[relative_path])
                if current_hash != baseline[relative_path]:
                    modified_paths.add(relative_path)
                    restore_file(target_dir, backup_dir, relative_path, "content was modified")

            # --- CREATED: on disk, not in baseline -> Quarantine ---
            new_paths = current_paths - baseline_paths
            for relative_path in sorted(new_paths):
                quarantine_file(target_dir, quarantine_dir, current_files[relative_path])

            if not (deleted_paths or new_paths or modified_paths):
                log("No changes detected. All files intact.", "INFO")

            time.sleep(interval)

    except KeyboardInterrupt:
        log("Monitoring stopped by user.", "WARN")
        sys.exit(0)


# ---------------------------------------------------------------------------
# COMMAND-LINE INTERFACE
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel.py",
        description="SentinelFIM - File Integrity Monitor with Self-Healing and Quarantine."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a baseline snapshot of a folder.")
    init_parser.add_argument("--path", required=True, help="Target directory to baseline.")

    monitor_parser = subparsers.add_parser("monitor", help="Continuously monitor a folder.")
    monitor_parser.add_argument("--path", required=True, help="Target directory to monitor.")
    monitor_parser.add_argument("--interval", type=int, default=5,
                                 help="Seconds between checks (default: 5).")

    return parser


def main():
    _enable_windows_ansi_support()
    parser = build_parser()
    args = parser.parse_args()

    target_dir = Path(args.path).expanduser().resolve()

    if args.command == "init":
        cmd_init(target_dir)
    elif args.command == "monitor":
        cmd_monitor(target_dir, args.interval)


if __name__ == "__main__":
    main()
