from scapy.all import ARP, Ether, srp
import socket
import threading


class NetworkScanner:
    def __init__(self):
        self.known_ports = {
            20: "FTP-DATA",
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
        }
        self.print_lock = threading.Lock()

    def get_local_ip(self):
        """Get the local IP address of the machine"""
        try:
            # Create a socket to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Connecting to Google's DNS
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return None

    def scan_ports(self, target_ip, ports, open_ports):
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Reduced timeout for faster scanning

                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    service = self.known_ports.get(port, "Unknown")
                    with self.print_lock:
                        open_ports.append(f"{port}: {service}")
                sock.close()
            except Exception as e:
                with self.print_lock:
                    print(f"Error scanning port {port}: {e}")

    def scan_host(self, target_ip, num_threads=100):
        open_ports = []
        threads = []
        ports = range(1, 1025)  # Scan first 1024 ports

        # Split ports among threads
        port_segments = list(self.split_list(list(ports), num_threads))

        # Create and start threads
        for ports_segment in port_segments:
            t = threading.Thread(
                target=self.scan_ports, args=(target_ip, ports_segment, open_ports)
            )
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        return sorted(open_ports, key=lambda x: int(x.split(":")[0]))

    def scan_network(self, ip_range):
        try:
            # Create ARP request packet
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            print("Sending ARP packets...")
            # Send packet and get response
            result = srp(packet, timeout=3, verbose=0)[0]

            if not result:
                print("No devices found. This might be because:")
                print(
                    "1. You're not running the script with administrator/root privileges"
                )
                print("2. The IP range doesn't match your network")
                print("3. Network firewall is blocking ARP requests")
                return []

            # Process results
            devices = []
            total_devices = len(result)
            print(f"\nFound {total_devices} devices on the network")

            for i, (sent, received) in enumerate(result, 1):
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    hostname = "Unknown"

                print(
                    f"\nScanning device {i}/{total_devices}: {received.psrc} ({hostname})..."
                )
                open_ports = self.scan_host(received.psrc)

                devices.append(
                    {
                        "ip": received.psrc,
                        "mac": received.hwsrc,
                        "hostname": hostname,
                        "open_ports": open_ports,
                    }
                )

            return devices

        except Exception as e:
            print(f"Error during network scan: {e}")
            print(
                "Make sure you're running the script with administrator/root privileges"
            )
            return []

    @staticmethod
    def split_list(lst, n):
        """Split a list into n roughly equal parts"""
        k, m = divmod(len(lst), n)
        return [lst[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(n)]

    def print_results(self, devices):
        print("\nNetwork Scan Results:")
        print("-" * 50)
        for device in devices:
            print(f"\nHost: {device['hostname']}")
            print(f"IP Address: {device['ip']}")
            print(f"MAC Address: {device['mac']}")
            if device["open_ports"]:
                print("Open Ports:")
                for port in device["open_ports"]:
                    print(f"  {port}")
            else:
                print("No open ports found")
            print("-" * 50)


def main():
    scanner = NetworkScanner()

    # Get local IP and determine network range
    local_ip = scanner.get_local_ip()
    if not local_ip:
        print("Could not determine local IP address. Exiting...")
        return

    # Convert IP to network range (assuming /24 subnet)
    ip_parts = local_ip.split(".")
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    print(f"Local IP: {local_ip}")
    print(f"Scanning network range: {ip_range}")
    print("\nNote: This script requires administrator/root privileges to run properly")

    devices = scanner.scan_network(ip_range)
    if devices:
        scanner.print_results(devices)
    else:
        print("\nNo devices were found on the network")


if __name__ == "__main__":
    main()
