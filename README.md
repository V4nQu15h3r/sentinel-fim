# SentinelFIM

**A cross-platform File Integrity Monitor with automated Self-Healing and Quarantine, built entirely on the Python Standard Library.**

SentinelFIM watches a directory, detects unauthorized change, and automatically corrects it — without requiring a single third-party dependency.

---

## Why SentinelFIM Exists

File Integrity Monitoring (FIM) is a foundational control in cybersecurity: it answers the question *"has anything in this directory changed since the last time I trusted it?"*

Manually auditing a directory tree for tampering means someone has to periodically list every file, remember (or record) what it used to look like, and manually compare it — a slow, error-prone process that doesn't scale and is almost never done in real time. SentinelFIM automates that entire workflow:

1. It takes a cryptographic snapshot of a directory (the **baseline**).
2. It continuously re-checks the directory against that baseline.
3. When it finds a discrepancy, it **acts immediately** — restoring tampered/deleted files and isolating unauthorized ones — instead of just alerting and waiting on a human.

### Enforcing the "I" in the CIA Triad

The CIA Triad — **Confidentiality, Integrity, Availability** — is the core model used to reason about security objectives. SentinelFIM is purpose-built around the **Integrity** pillar: the guarantee that data has not been altered in an unauthorized or undetected way.

It enforces this in two complementary ways:

- **Detection:** Every file is fingerprinted with SHA-256. Any modification, no matter how small, produces a completely different hash, making silent tampering mathematically infeasible to hide.
- **Enforcement:** Detection alone only tells you *that* something broke. SentinelFIM goes further and closes the loop — automatically reverting unauthorized changes and neutralizing unauthorized additions — so integrity is actively *maintained*, not just monitored.

---

## Features

| Feature | Description |
|---|---|
| **OS-Agnostic** | Built entirely on `pathlib`, `os`, `shutil`, `json`, `time`, and `hashlib`. Runs identically on Windows, macOS, and Linux with zero external dependencies. |
| **Chunk-Based Hashing** | Files are hashed in 4096-byte chunks rather than loaded fully into memory, so SentinelFIM can safely fingerprint massive files (e.g. multi-gigabyte logs) without crashing or exhausting RAM. |
| **Self-Healing** | If a baselined file is **modified** or **deleted**, SentinelFIM automatically restores it from a local, versionless backup and logs the corrective action. |
| **Quarantine** | If a **new, unauthorized** file appears in a monitored directory, SentinelFIM immediately isolates it into a `.quarantine/` folder and strips its write/execute permissions via `os.chmod`, neutralizing it in place. |
| **Timestamped Logging** | Every scan and every corrective action is printed to the terminal with a clear timestamp and an explicit action tag (`[RESTORED]`, `[QUARANTINED]`, etc.), so the tool is transparent and auditable. |

---

## Repository Structure

```
sentinel-fim/
├── src/
│   └── sentinel.py       # The CLI tool itself
├── tests/
│   └── test_fim.py       # Unit tests for core hashing logic
├── .gitignore
├── requirements.txt       # Intentionally empty — stdlib only
└── README.md
```

---

## Requirements

- Python 3.8 or later
- No external packages (see `requirements.txt`)

---

## Installation

```bash
git clone https://github.com/INVIZIBLE84/sentinel-fim.git
cd sentinel-fim
```

That's it — there's nothing to `pip install`.

---

## Usage

### 1. Initialize a baseline

Point SentinelFIM at any directory you want to protect. This hashes every file inside it, saves those fingerprints to a hidden `.baseline.json`, and stores a recovery copy of every file in a hidden `.backup/` folder.

```bash
python src/sentinel.py init --path /path/to/target_directory
```

### 2. Start monitoring

Runs continuously, re-scanning the target directory on a fixed interval and taking corrective action the moment it detects a discrepancy.

```bash
python src/sentinel.py monitor --path /path/to/target_directory --interval 5
```

- `--path` — the directory to watch (required)
- `--interval` — seconds between scans (optional, default: `5`)

Stop monitoring at any time with `Ctrl+C`.

### What happens during monitoring

| Detected State | Condition | SentinelFIM's Response |
|---|---|---|
| `MODIFIED` | A baselined file's hash no longer matches | Overwrite it with the clean copy from `.backup/` → `[RESTORED]` |
| `DELETED` | A baselined file is missing from disk | Recreate it from `.backup/` → `[RESTORED]` |
| `CREATED` (unauthorized) | A file exists that was never in the baseline | Move it to `.quarantine/` and strip write/execute permissions → `[QUARANTINED]` |

### Example output

```
[2026-07-04 10:15:02] [INFO] Monitoring '/path/to/target_directory' every 5 second(s). Press Ctrl+C to stop.
[2026-07-04 10:15:07] [RESTORED] index.html  (reason: content was modified)
[2026-07-04 10:15:07] [QUARANTINED] unknown_script.py  -> moved to .quarantine/ and locked read-only
[2026-07-04 10:15:12] [INFO] No changes detected. All files intact.
```

---

## Running the Tests

Unit tests cover the core hashing function that all integrity checks depend on — verifying that hashing is deterministic, that any content change produces a different hash, and that large files are handled safely via chunked reads.

From the repository root:

```bash
python -m unittest discover -s tests -v
```

---

## Notes on Housekeeping Files

`.baseline.json`, `.backup/`, and `.quarantine/` are created **inside** the directory you monitor. They are excluded from SentinelFIM's own file scanning (so it never quarantines itself) and are excluded from version control via `.gitignore`, since they represent machine-specific runtime state rather than source code.

If you intentionally add new files to a monitored directory, re-run `init` to refresh the baseline — otherwise SentinelFIM will treat them as unauthorized on the next scan.

