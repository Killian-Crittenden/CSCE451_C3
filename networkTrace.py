import psutil
import subprocess
import pyshark
import sys
from multiprocessing import Process, Event


def analyze_packet(packet, interface):
    """
    Analyze a single packet and log useful details.

    :param packet: The captured packet.
    :param interface: The network interface being monitored.
    """
    try:
        # Basic packet details
        timestamp = packet.sniff_time
        protocol = packet.highest_layer
        length = packet.length

        # Log DNS traffic
        if 'DNS' in packet:
            dns_query = packet.dns.qry_name if 'qry_name' in packet.dns else "Unknown Query"
            print(f"[{interface}] {timestamp} - DNS Query: {dns_query} - Protocol: {protocol} - Length: {length} bytes")
            return

        # Log HTTP/HTTPS traffic
        if protocol in ['HTTP', 'HTTPS']:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            http_method = packet.http.request_method if hasattr(packet.http, 'request_method') else "Unknown Method"
            uri = packet.http.request_full_uri if hasattr(packet.http, 'request_full_uri') else "Unknown URI"
            print(f"[{interface}] {timestamp} - HTTP {http_method} to {uri} - {src_ip} -> {dst_ip} - Length: {length} bytes")
            return

        # Log Encrypted (TLS) traffic
        if protocol == 'TLS':
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            tls_version = packet.tls.handshake_version if hasattr(packet.tls, 'handshake_version') else "Unknown TLS Version"
            print(f"[{interface}] {timestamp} - Encrypted Traffic (TLS {tls_version}) - {src_ip} -> {dst_ip} - Length: {length} bytes")
            return

        # Log other traffic
        if 'TCP' in packet or 'UDP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport if 'TCP' in packet else packet.udp.srcport
            dst_port = packet.tcp.dstport if 'TCP' in packet else packet.udp.dstport
            print(f"[{interface}] {timestamp} - {src_ip}:{src_port} -> {dst_ip}:{dst_port} - Protocol: {protocol} - Length: {length} bytes")

    except AttributeError:
        # Ignore packets without relevant details
        pass


def capture_packets(stop_event):
    """
    Capture packets on the 'eth0' network interface and analyze them.

    :param stop_event: Event to signal capture termination.
    """
    interface = "eth0"
    try:
        print(f"Starting capture on interface '{interface}'...")

        # Use a Pyshark LiveCapture with filtering for specific protocols
        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter="dns or http or tls or tcp or udp"
        )

        for packet in capture.sniff_continuously():
            if stop_event.is_set():
                print(f"Stopping capture on '{interface}'.")
                break

            analyze_packet(packet, interface)

    except Exception as e:
        print(f"Error capturing on interface '{interface}': {e}")
    finally:
        print(f"Capture on '{interface}' finished.")


def run_executable_and_capture(executable_path):
    """
    Run the executable and capture traffic on the 'eth0' interface.

    :param executable_path: Path to the executable to monitor.
    """
    print(f"Capturing on 'eth0' and running executable: {executable_path}")
    
    # Run the executable as a subprocess
    try:
        executable_process = subprocess.Popen(
            executable_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except Exception as e:
        print(f"Error running the executable: {e}")
        sys.exit(1)

    # Start capturing traffic
    stop_event = Event()
    capture_process = Process(target=capture_packets, args=(stop_event,))
    capture_process.start()

    # Wait for the executable process to finish or handle interruption
    try:
        executable_process.wait()
        print("Executable process finished.")
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected. Stopping capture.")
    finally:
        stop_event.set()
        capture_process.join()


def main():
    # Get the path to the executable from the user
    executable_path = input("Enter the path to the executable: ").strip()
    if not executable_path:
        print("Error: Executable path is required.")
        sys.exit(1)

    # Run the executable and capture traffic on 'eth0'
    run_executable_and_capture(executable_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
