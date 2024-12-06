import os
import hashlib
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import subprocess
import sys


class FileActivityHandler(FileSystemEventHandler):
    def __init__(self, backup_dir):
        self.backup_dir = backup_dir
        self.file_hashes = {}  # Dictionary to track file hashes

        # Ensure the backup directory exists
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

    def compute_hash(self, file_path):
        """Compute the hash of a file using SHA-256."""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):  # Read in 4KB chunks
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except FileNotFoundError:
            return None

    def backup_file(self, src_path):
        """Backup a file to the backup directory."""
        if os.path.exists(src_path):
            file_name = os.path.basename(src_path)
            backup_path = os.path.join(self.backup_dir, file_name)    
            try:
                shutil.copy2(src_path, backup_path)
            except shutil.SameFileError:
                pass
            except FileNotFoundError:
                print("File was not found when backup was trying to be made")
                return -1
            print(f"Backup created for: {src_path} at {backup_path}")
            return 0

    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            file_path = event.src_path
            print(f"File created: {file_path}")
            new_hash = self.compute_hash(file_path)
            if new_hash:
                if self.backup_file(file_path) == -1:
                    print("On file creation backup threw an error")
                self.file_hashes[file_path] = new_hash

    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            file_path = event.src_path
            new_hash = self.compute_hash(file_path)
            # Check if the hash has changed
            if file_path not in self.file_hashes or self.file_hashes[file_path] != new_hash:
                print(f"File modified: {file_path}")
                if self.backup_file(file_path) == -1:
                    print("On file modification backup threw an error")
                self.file_hashes[file_path] = new_hash

    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            file_path = event.src_path
            print(f"File deleted: {file_path}")
            if file_path in self.file_hashes:
                del self.file_hashes[file_path]


def main():
    # Directory to monitor and backup location
    directory_to_monitor = "."
    backup_directory = "./backup"
    no_delete = False

    if len(sys.argv) > 1:
        for i in range(len(sys.argv)):
            if (sys.argv[i]) == "-d":
                print("no delete mode activated")
                no_delete = True
                result = subprocess.run(["sudo", "chattr", "-R", "+a", "."], capture_output=True, text=True)


    # Create an event handler and observer
    handler = FileActivityHandler(backup_dir=backup_directory)
    observer = Observer()
    observer.schedule(handler, path=directory_to_monitor, recursive=True)

    # Start the observer
    observer.start()
    print("Monitoring started. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)  # Keep the program running
    except KeyboardInterrupt:
        print("Monitoring stopped.")
        observer.stop()

    observer.join()

    if (no_delete):
        result = subprocess.run(["sudo", "chattr", "-R", "-a", "."], capture_output=True, text=True)



if __name__ == "__main__":
    main()
