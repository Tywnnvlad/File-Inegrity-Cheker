# File Integrity Checker

A Python script to monitor file integrity within a directory by comparing SHA256 hashes against a stored baseline.
https://roadmap.sh/projects/file-integrity-checker

## Description

This script provides a simple way to detect changes, additions, or deletions of files within a specified directory (and its subdirectories). It works by:

1.  **Generating** a baseline: Calculating the SHA256 hash for each file and storing it in a log file (`log/hash.log`).
2.  **Verifying** against the baseline: Recalculating hashes for current files and comparing them to the stored hashes in the log file.

This is useful for ensuring that critical files haven't been tampered with or accidentally modified.

## Features

*   Calculates SHA256 hashes for files.
*   Recursively scans directories.
*   Excludes common directories/files like `.git`, `.pyc`, and the hash log itself.
*   Generates a `hash.log` file to store baseline hashes.
*   Verifies current file hashes against the baseline.
*   Reports:
    *   Files with hash mismatches (content changed).
    *   Files missing (present in log but not found on disk).
    *   New files detected (present on disk but not in log).

## Requirements

*   Python 3.x

## Usage

The script is run from the command line using `python log/file-integrity-check.py` followed by an optional command.

**Commands:**

1.  **`generate`**: Create or update the baseline hash log.
    ```bash
    python log/file-integrity-check.py generate
    ```
    This command scans the current directory (`.`) and saves the hashes to `log/hash.log`. **Warning:** This overwrites the existing `log/hash.log`.

2.  **`verify`**: Compare the current state of files against the baseline in `log/hash.log`. This is the **default** action if no command is specified.
    ```bash
    python log/file-integrity-check.py verify
    ```
    or simply:
    ```bash
    python log/file-integrity-check.py
    ```
    This command will print a report detailing any mismatches, missing files, or new files found.

3.  **`help`**: Display the help message with usage instructions.
    ```bash
    python log/file-integrity-check.py help
    ```

## How it Works

*   **Hashing:** Uses Python's `hashlib` library to compute the SHA256 hash of each file's content.
*   **Log File:** Stores the relative path and corresponding hash for each file found during the `generate` phase.
*   **Comparison:** During `verify`, it recalculates hashes and compares them against the log file entries. It also checks for files listed in the log but missing from the disk, and files on the disk not listed in the log.

## Exclusions

The script automatically skips the following during hashing and verification:
*   The `.git` directory.
*   Python bytecode files (`.pyc`).
*   The hash log file itself (`log/hash.log`).
