import os
import hashlib
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import subprocess
import sys
import psutil
import pyshark
import socket
from threading import Thread

directory_to_monitor = "."
backup_directory = "./backup"
process_log = os.path.join(backup_directory, "process_log.txt")
network_trace_log = os.path.join(backup_directory, "network_trace_log.txt")

class ProcessMonitor:
    def __init__(self, log_file="process_log.txt", interval=0.01):
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
            # Modify ps command to include pid, ppid, user, and command
            result = subprocess.run(['ps', '-eo', 'pid,ppid,user,comm'], stdout=subprocess.PIPE, text=True)
            lines = result.stdout.strip().split("\n")[1:]  # Skip the header
            processes = {}
            
            for line in lines:
                parts = line.split(None, 3)  # Split into 4 parts: pid, ppid, user, and comm
                pid = int(parts[0])
                ppid = int(parts[1])
                user = parts[2]
                command = parts[3] if len(parts) > 3 else ""
                if ppid != os.getpid():
                    processes[pid] = {'ppid': ppid, 'user': user, 'command': command}
            
            return processes
        except Exception as e:
            print(f"Error fetching processes using subprocess: {e}")
            return {}

    def log_process_details_psutil(self, pid):
        """Log details of a new process using psutil."""
        try:
            proc = psutil.Process(pid)
            log_entry = (f"[psutil] New Process Detected - PID: {pid}, Name: {proc.name()}, "
                         f"Command: {proc.cmdline()}, Timestamp: {time.ctime(proc.create_time())}\n")
            #print(log_entry.strip())
            with open(self.log_file, "a") as f:
                f.write(log_entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            #print(f"[psutil] Process {pid} terminated before it could be logged.")
            pass

    def log_process_details_subprocess(self, pid, command):
        """Log details of a new process using subprocess."""
        log_entry = f"[subprocess] New Process Detected - PID: {pid}, Command: {command}, Timestamp: {time.ctime()}\n"
        #print(log_entry.strip())
        with open(self.log_file, "a") as f:
            f.write(log_entry)

class FileActivityHandler(FileSystemEventHandler):
    def __init__(self, backup_dir):
        self.backup_dir = backup_dir
        self.file_hashes = {}  # Dictionary to track file hashes

        # Create backup directory if not exist
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
            if (src_path == backup_path or src_path == network_trace_log):
                return 0    
            try:
                shutil.copy2(src_path, backup_path)
            except shutil.SameFileError:
                pass
            except FileNotFoundError:
                print("File was not found when backup was trying to be made, run with -d flag to remove the ability for the program to delete files.")
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
            if (file_path == process_log):
                return 0
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


def get_active_interface():
    """
    Determine the first active network interface.
    Returns:
        str: The name of the active interface, or None if no active interface is found.
    """
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, stat in stats.items():
        if stat.isup and iface != "lo":  # Exclude loopback
            return iface
    return None  # No active interface found

def get_local_ip(interface):
    """
    Determine the local IP address of a given network interface.
    Args:
        interface (str): The name of the network interface.
    Returns:
        str: The local IP address associated with the interface, or None if not found.
    """
    addrs = psutil.net_if_addrs()
    if interface in addrs:
        for addr in addrs[interface]:
            if addr.family == socket.AF_INET:  # IPv4 address
                return addr.address
    return None




def tcp_flags_to_string(flags):
    """
    Convert TCP flags from hexadecimal representation to human-readable abbreviations.
    """
    flag_dict = {
        0x01: "FIN",  # Finish
        0x02: "SYN",  # Synchronize
        0x04: "RST",  # Reset
        0x08: "PSH",  # Push
        0x10: "ACK",  # Acknowledgement
        0x20: "URG",  # Urgent
        0x40: "ECE",  # ECN Echo
        0x80: "CWR",  # Congestion Window Reduced
    }

    # Convert the hexadecimal flag value to an integer
    flag_value = int(flags, 16) if isinstance(flags, str) else flags
    active_flags = [flag for bitmask, flag in flag_dict.items() if flag_value & bitmask]
    
    return ", ".join(active_flags) if active_flags else "N/A"

def capture_packets(log_file):
    """
    Capture network packets and log them to the specified log file.
    Dynamically selects the active network interface.
    """
    try:
        interface = get_active_interface()
        if not interface:
            print("No active network interface found. Exiting.")
            return

        local_ip = get_local_ip(interface)
        if not local_ip:
            print(f"Could not determine local IP address for interface {interface}. Exiting.")
            return

        print(f"Starting network packet capture on interface: {interface} (Local IP: {local_ip})")
        capture = pyshark.LiveCapture(interface=interface, display_filter="dns or http or tls or tcp or udp or icmp")

        # Log packet data continuously
        with open(log_file, "a") as f:
            packet_count = 0  # To track packet numbers
            protocol_counts = {}  # To track protocol counts

            for packet in capture.sniff_continuously():
                try:
                    # General details
                    packet_count += 1
                    timestamp = packet.sniff_time
                    protocol = packet.highest_layer
                    length = packet.length
                    src_ip = packet.ip.src if hasattr(packet, "ip") else "N/A"
                    dst_ip = packet.ip.dst if hasattr(packet, "ip") else "N/A"
                    captured_interface = packet.interface_captured_on if hasattr(packet, "interface_captured_on") else interface

                    # Protocol-specific details
                    src_port = packet.tcp.srcport if hasattr(packet, "tcp") else (
                        packet.udp.srcport if hasattr(packet, "udp") else "N/A")
                    dst_port = packet.tcp.dstport if hasattr(packet, "tcp") else (
                        packet.udp.dstport if hasattr(packet, "udp") else "N/A")
                    tcp_flags = tcp_flags_to_string(packet.tcp.flags) if hasattr(packet, "tcp") else "N/A"
                    http_method = packet.http.request_method if hasattr(packet, "http") else "N/A"
                    tls_sni = packet.tls.handshake_extensions_server_name if hasattr(packet, "tls") else "N/A"
                    dns_query = packet.dns.qry_name if hasattr(packet, "dns") else "N/A"
                    dns_response = packet.dns.a if hasattr(packet, "dns") else "N/A"

                    # Packet direction
                    direction = "Outbound" if src_ip == local_ip else ("Inbound" if dst_ip == local_ip else "Unknown")

                    # Update protocol counts
                    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

                    # Log entry
                    log_entry = (f"[Packet #{packet_count}] Interface: {captured_interface} - {timestamp} - {protocol} - "
                                 f"Length: {length} bytes - Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port} - "
                                 f"Direction: {direction} - TCP Flags: {tcp_flags} - HTTP Method: {http_method} - "
                                 f"TLS SNI: {tls_sni} - DNS Query: {dns_query}, DNS Response: {dns_response}\n")
                    f.write(log_entry)
                    # print(log_entry.strip())
                except AttributeError as attr_err:
                    # Handle packets without expected attributes
                    error_entry = f"[Error] Packet could not be parsed: {attr_err}\n"
                    f.write(error_entry)
                    # print(error_entry.strip())
                except Exception as e:
                    # Catch any unexpected errors during packet processing
                    error_entry = f"[Error] Unexpected error: {e}\n"
                    f.write(error_entry)
                    # print(error_entry.strip())
    except Exception as e:
        print(f"Error capturing packets: {e}")





def start_packet_capture_thread(log_file):
    """
    Start the packet capture in a separate thread.
    Dynamically selects the active network interface.
    """
    print("Starting packet capture thread...")
    packet_capture_thread = Thread(target=capture_packets, args=(log_file,))
    packet_capture_thread.daemon = True  # Allows the thread to exit when the main program exits
    packet_capture_thread.start()
    return packet_capture_thread


def main():
    no_delete = False
    dir_specified = False
    observers = []

    if len(sys.argv) > 1:
        for i in range(len(sys.argv)):
            if (sys.argv[i]) == "-n":
                print("no delete mode activated")
                no_delete = True
                result = subprocess.run(["sudo", "chattr", "-R", "+a", "."], capture_output=True, text=True)
            if (sys.argv[i]) == "-d":
                dir_specified = True
                dir = sys.argv[i+1]
                handler = FileActivityHandler(backup_dir=backup_directory)
                observer = Observer()
                observer.schedule(handler, path=dir, recursive=True)
                observers.append(observer)


    # Ensure log files are cleared at startup
    with open(network_trace_log, "w") as f:
        f.write("Network Trace Log\n")
        f.write("=" * 50 + "\n")


    # Create an event handler and observer
    if (dir_specified == False):
        handler = FileActivityHandler(backup_dir=backup_directory)
        observer = Observer()
        observer.schedule(handler, path=directory_to_monitor, recursive=True)
        observers.append(observer)

    start_packet_capture_thread(network_trace_log)

    # Start the observer
    for i in range(len(observers)):
        observers[i].start()
    
    pmonitor = ProcessMonitor(log_file=process_log)
    pmonitor.update_existing_processes()
    print("Monitoring started. Press Ctrl+C to stop.")
    try:
        while True:
            # Use psutil to track processes
                current_psutil_pids = {proc.pid for proc in psutil.process_iter(['pid', 'name'])}
                # Use subprocess to track processes
                current_subprocess_processes = pmonitor.get_processes_using_ps()

                # Identify new PIDs (common across both methods)
                new_psutil_pids = current_psutil_pids - pmonitor.existing_pids
                new_subprocess_pids = set(current_subprocess_processes.keys()) - pmonitor.existing_pids

                # Log details for psutil
                for pid in new_psutil_pids:
                    pmonitor.log_process_details_psutil(pid)

                # Log details for subprocess
                for pid in new_subprocess_pids:
                    pmonitor.log_process_details_subprocess(pid, current_subprocess_processes[pid])

                pmonitor.existing_pids = current_psutil_pids  # Update existing PIDs for psutil
                time.sleep(pmonitor.interval)
    except KeyboardInterrupt:
        print("Monitoring stopped.")
        for i in range(len(observers)):
            observers[i].stop()
        pass

    observer.join()

    if (no_delete):
        result = subprocess.run(["sudo", "chattr", "-R", "-a", "."], capture_output=True, text=True)

    print("Program exiting")

    

    



if __name__ == "__main__":
    main()


