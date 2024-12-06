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

        # Log ICMP traffic
        if 'ICMP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            icmp_type = packet.icmp.type if hasattr(packet.icmp, 'type') else "Unknown"
            icmp_code = packet.icmp.code if hasattr(packet.icmp, 'code') else "Unknown"
            icmp_desc = "Echo Request" if icmp_type == "8" else "Echo Reply" if icmp_type == "0" else f"Type {icmp_type}, Code {icmp_code}"
            print(f"[{interface}] {timestamp} - ICMP {icmp_desc} - {src_ip} -> {dst_ip} - Length: {length} bytes")
            return

    except AttributeError:
        # Ignore packets without relevant details
        pass


def capture_packets(interface):
    """
    Continuously capture packets on the specified network interface and analyze them.

    :param interface: The network interface to monitor.
    """
    try:
        print(f"Starting capture on interface '{interface}'...")

        # Use a Pyshark LiveCapture with filtering for specific protocols
        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter="dns or http or tls or tcp or udp or icmp"
        )

        for packet in capture.sniff_continuously():
            analyze_packet(packet, interface)

    except KeyboardInterrupt:
        print("\nCtrl+C detected. Stopping capture.")
    except Exception as e:
        print(f"Error capturing on interface '{interface}': {e}")
    finally:
        print(f"Capture on '{interface}' finished.")


def run_executable_and_capture(executable_path, interface):
    """
    Run the executable and continuously capture traffic on the specified interface.

    :param executable_path: Path to the executable to monitor.
    :param interface: The network interface to monitor.
    """
    print(f"Capturing on '{interface}' and running executable: {executable_path}")
    
    # Run the executable as a subprocess
    try:
        executable_process = subprocess.Popen(
            executable_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except Exception as e:
        print(f"Error running the executable: {e}")
        sys.exit(1)

    # Start capturing traffic in a while loop
    try:
        capture_packets(interface)
        executable_process.wait()
        print("Executable process finished.")
    except KeyboardInterrupt:
        print("\nCtrl+C detected. Stopping executable and capture.")
    finally:
        executable_process.terminate()


def main():
    # Get the path to the executable from the user
    executable_path = input("Enter the path to the executable: ").strip()
    if not executable_path:
        print("Error: Executable path is required.")
        sys.exit(1)

    # Get the interface to monitor
    interface = input("Enter the network interface to monitor (default: eth0): ").strip() or "eth0"

    # Run the executable and capture traffic on the specified interface
    run_executable_and_capture(executable_path, interface)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
