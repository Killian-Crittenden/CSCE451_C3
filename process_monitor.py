import psutil
import subprocess
import time

class ProcessMonitor:
    def __init__(self, log_file="process_log.txt", interval=1):
        self.log_file = log_file
        self.interval = interval  # Time interval between checks (in seconds)
        self.existing_pids = set()

        # Initialize the log file
        with open(self.log_file, "w") as f:
            f.write("Process Monitor Log\n")
            f.write("=" * 50 + "\n")

    def update_existing_processes(self):
        """Initialize the list of existing processes."""
        self.existing_pids = {proc.pid for proc in psutil.process_iter(['pid'])}

    def get_processes_using_ps(self):
        """Get process details using subprocess (Linux/Mac)."""
        try:
            result = subprocess.run(['ps', '-eo', 'pid,comm'], stdout=subprocess.PIPE, text=True)
            lines = result.stdout.strip().split("\n")[1:]  # Skip the header
            processes = {int(line.split(None, 1)[0]): line.split(None, 1)[1] for line in lines}
            return processes
        except Exception as e:
            print(f"Error fetching processes using subprocess: {e}")
            return {}

    def monitor_new_processes(self):
        """Monitor for new processes using psutil."""
        print("Monitoring for new processes. Press Ctrl+C to stop.")
        try:
            while True:
                # Use psutil to track processes
                current_psutil_pids = {proc.pid for proc in psutil.process_iter(['pid', 'name'])}
                # Use subprocess to track processes
                current_subprocess_processes = self.get_processes_using_ps()

                # Identify new PIDs (common across both methods)
                new_psutil_pids = current_psutil_pids - self.existing_pids
                new_subprocess_pids = set(current_subprocess_processes.keys()) - self.existing_pids

                # Log details for psutil
                for pid in new_psutil_pids:
                    self.log_process_details_psutil(pid)

                # Log details for subprocess
                for pid in new_subprocess_pids:
                    self.log_process_details_subprocess(pid, current_subprocess_processes[pid])

                self.existing_pids = current_psutil_pids  # Update existing PIDs for psutil
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("Monitoring stopped.")

    def log_process_details_psutil(self, pid):
        """Log details of a new process using psutil."""
        try:
            proc = psutil.Process(pid)
            log_entry = (f"[psutil] New Process Detected - PID: {pid}, Name: {proc.name()}, "
                         f"Command: {proc.cmdline()}, Timestamp: {time.ctime(proc.create_time())}\n")
            print(log_entry.strip())
            with open(self.log_file, "a") as f:
                f.write(log_entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print(f"[psutil] Process {pid} terminated before it could be logged.")

    def log_process_details_subprocess(self, pid, command):
        """Log details of a new process using subprocess."""
        log_entry = f"[subprocess] New Process Detected - PID: {pid}, Command: {command}, Timestamp: {time.ctime()}\n"
        print(log_entry.strip())
        with open(self.log_file, "a") as f:
            f.write(log_entry)

def main():
    monitor = ProcessMonitor(log_file="process_log.txt", interval=1)
    monitor.update_existing_processes()
    monitor.monitor_new_processes()

if __name__ == "__main__":
    main()
