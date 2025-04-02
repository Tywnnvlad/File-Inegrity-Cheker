import os
import sys
import hashlib
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def comparehash(hash1, hash2):
    """Compares two hash strings."""
    # Note: The original print statements had issues. Corrected below.
    # print(f"{hash1}\n") # Usually not needed to print here
    # print(f"{hash2}\n")
    return hash1 == hash2

def parse_hash_log_file(log_file_path):
    """Parse a log file containing SHA256 hashes and return a dictionary of {filename: hash}."""
    hash_dict = {}
    # Regex pattern to extract filename and hash (relative paths assumed for simplicity)
    pattern = r'SHA256\((.*?)\):\s+([a-f0-9]{64})'

    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                line = line.strip()  # Remove leading/trailing whitespace
                if not line:  # Skip empty lines
                    continue

                match = re.search(pattern, line)
                if match:
                    # Normalize path separators for consistency
                    filename = os.path.normpath(match.group(1))
                    file_hash = match.group(2)
                    hash_dict[filename] = file_hash
    except FileNotFoundError:
        logger.error(f"Log file not found: {log_file_path}")
        print(f"Error: Log file '{log_file_path}' not found.")
    except Exception as e:
        logger.error(f"Error reading log file {log_file_path}: {e}")
        print(f"Error: Could not read log file '{log_file_path}'.")

    return hash_dict


def encryptsha256(file_path):
    """Calculate the SHA256 hash of a file."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as file:
            # Read the file in chunks to avoid memory issues with large files
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    except FileNotFoundError:
        # Logged during verification, might be expected if file was deleted
        # logger.error(f"File not found: {file_path}")
        return None # Indicate file couldn't be hashed (likely missing)
    except PermissionError:
        logger.error(f"Permission denied: {file_path}")
        print(f"Warning: Permission denied for file '{file_path}'. Skipping.")
    except Exception as e:
        logger.error(f"Unexpected error while hashing file {file_path}: {e}")
        print(f"Warning: Error hashing file '{file_path}'. Skipping.")
    return None # Indicate error during hashing


def reset_log(path):
    """Overwrite a file (log file)."""
    try:
        with open(path, "w") as f:
            f.write("")
        logger.info(f"Log file reset: {path}")
    except Exception as e:
        logger.error(f"Failed to reset log file {path}: {e}")
        print(f"Error: Failed to reset log file '{path}'.")


def generate_hashes(directory=".", log_file_path="log/hash.log"):
    """Generate SHA256 hashes for all files in a directory and save to a log file."""
    logger.info(f"Generating hashes for directory: {directory}")
    reset_log(log_file_path) # Reset log before generating new hashes

    output_lines = []
    abs_log_path = os.path.abspath(log_file_path)

    # Walk through the specified directory
    for root, dirs, files in os.walk(directory, topdown=True):
        # Exclude .git directory (common practice)
        dirs[:] = [d for d in dirs if d != '.git']
        # Exclude hidden files/dirs if desired (optional)
        # dirs[:] = [d for d in dirs if not d.startswith('.')]
        # files = [f for f in files if not f.startswith('.')]

        for file_name in files:
            file_path = os.path.join(root, file_name)
            abs_file_path = os.path.abspath(file_path)

            # Avoid hashing the log file itself
            if abs_file_path == abs_log_path:
                logger.debug(f"Skipping log file: {file_path}")
                continue

            # Avoid hashing .pyc files (Python bytecode)
            if file_name.endswith(".pyc"):
                 logger.debug(f"Skipping bytecode file: {file_path}")
                 continue

            hash_value = encryptsha256(file_path)
            if hash_value:
                # Store relative paths in the log file
                relative_path = os.path.normpath(file_path)
                output_lines.append(f"SHA256({relative_path}): {hash_value}")
                logger.debug(f"Hashed {relative_path}: {hash_value}")
            else:
                 logger.warning(f"Could not generate hash for {file_path}")


    # Write all hashes to the log file at once
    try:
        with open(log_file_path, "w") as log_file:
            log_file.write("\n".join(sorted(output_lines)) + "\n") # Sort for consistent logs
        logger.info(f"Hashes generated and saved to {log_file_path}")
        print(f"Hash generation complete. Log saved to '{log_file_path}'.")
    except Exception as e:
        logger.error(f"Failed to write hashes to log file {log_file_path}: {e}")
        print(f"Error: Failed to write hashes to log file '{log_file_path}'.")


def verify_hashes(directory=".", log_file_path="log/hash.log"):
    """Verify file integrity by comparing current hashes with those in the log file."""
    logger.info(f"Starting hash verification for directory: {directory}")
    print(f"\n--- Verifying file integrity against '{log_file_path}' ---")
    stored_hashes = parse_hash_log_file(log_file_path)

    if not stored_hashes:
        print("Error: Could not load stored hashes or log file is empty.")
        print("Run with 'generate' command first to create the hash log.")
        return

    mismatched_files = []
    missing_files = list(stored_hashes.keys()) # Start with all files from log as potentially missing
    new_files = []
    processed_files = set() # Keep track of files found on disk
    abs_log_path = os.path.abspath(log_file_path)

    # Walk through the directory again to get current files
    for root, dirs, files in os.walk(directory, topdown=True):
         # Exclude .git directory
        dirs[:] = [d for d in dirs if d != '.git']
        # Optional: Exclude hidden items
        # dirs[:] = [d for d in dirs if not d.startswith('.')]
        # files = [f for f in files if not f.startswith('.')]

        for file_name in files:
            file_path = os.path.join(root, file_name)
            abs_file_path = os.path.abspath(file_path)
            relative_path = os.path.normpath(file_path)
            processed_files.add(relative_path) # Mark this file as seen

            # Skip the log file itself and bytecode
            if abs_file_path == abs_log_path or file_name.endswith(".pyc"):
                continue

            current_hash = encryptsha256(file_path)

            if relative_path in stored_hashes:
                if relative_path in missing_files:
                    missing_files.remove(relative_path) # File found

                stored_hash = stored_hashes[relative_path]
                if current_hash is None:
                     # Error hashing file (permission issue, etc.) - already printed warning
                     logger.warning(f"Could not hash file {file_path}. Cannot verify.")
                     # Optionally add to a separate 'unverifiable' list
                elif not comparehash(current_hash, stored_hash):
                    logger.warning(f"Hash mismatch for {file_path}. Stored: {stored_hash}, Current: {current_hash}")
                    mismatched_files.append(relative_path)
                # else: # Hash matches - uncomment for verbose success logging
                #    logger.info(f"Hash verified for {file_path}")
            else:
                # This file exists now but wasn't in the log
                if current_hash is not None: # Only report as new if we could hash it
                    logger.info(f"New file detected: {file_path}")
                    new_files.append(relative_path)

    # Any file still in missing_files wasn't found during the walk
    # Double-check they weren't processed but somehow missed removal (shouldn't happen)
    missing_files = [f for f in missing_files if f not in processed_files]


    # Report results
    print("\n--- Verification Report ---")
    if not mismatched_files and not missing_files and not new_files:
        print("OK: All files verified successfully.")
    else:
        if mismatched_files:
            print("\nWARNING: Files with HASH MISMATCH (content changed):")
            for f in sorted(mismatched_files):
                print(f"  - {f}")
        else:
            print("\nOK: No hash mismatches detected.")

        if missing_files:
            print("\nWARNING: Files MISSING (present in log but not found):")
            for f in sorted(missing_files):
                print(f"  - {f}")
        else:
            print("\nOK: No missing files detected.")

        if new_files:
            print("\nINFO: NEW files detected (present on disk but not in log):")
            for f in sorted(new_files):
                print(f"  - {f}")
        else:
            print("\nOK: No new files detected.")

    print("\n--- End Report ---")


def print_usage():
    """Prints the usage instructions."""
    script_name = os.path.basename(sys.argv[0])
    print(f"\nUsage: python {script_name} [command]")
    print("\nCommands:")
    print("  generate   - Generate/update hashes for files and save to log/hash.log")
    print("  verify     - Verify current file hashes against those in log/hash.log (default)")
    print("  help       - Display this help message")
    print("\nDescription:")
    print("  This script calculates SHA256 hashes for files in the current directory")
    print("  (and subdirectories, excluding .git) to detect changes, additions, or deletions.")


# Main execution logic
if __name__ == "__main__":
    args = sys.argv[1:] # Get arguments, excluding the script name itself
    num_args = len(args)
    log_file = "log/hash.log" # Define log file path relative to script location or CWD
    # Ensure the log directory exists
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)


    command = "verify" # Default command

    if num_args == 1:
        command = args[0].lower() # Make command case-insensitive
    elif num_args > 1:
        print(f"Error: Expected 0 or 1 argument, but got {num_args}.")
        print_usage()
        sys.exit(1) # Exit with error code

    # Execute command
    if command == "generate":
        generate_hashes(directory=".", log_file_path=log_file)
    elif command == "verify":
        verify_hashes(directory=".", log_file_path=log_file)
    elif command == "help":
        print_usage()
    else:
        print(f"Error: Unknown command '{args[0]}'")
        print_usage()
        sys.exit(1) # Exit with error code