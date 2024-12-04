# Network Scanner

A Python-based network scanning tool that discovers devices on your local network and identifies their open ports and running services.

## Features

- Discovers all devices connected to your local network using ARP scanning
- Performs multi-threaded port scanning on discovered devices
- Identifies common services running on open ports
- Displays device information including:
  - IP address
  - MAC address
  - Hostname (when available)
  - Open ports and their associated services

## Prerequisites

- Python 3.6 or higher
- Administrator/root privileges (required for ARP scanning)
- Operating systems: Windows, Linux, or macOS

## Installation

1. Clone the repository:

```bash
git clone https://github.com/FrankMike/netscanner.git
```

2. Install the required dependencies

```bash
pip install -r requirements.txt
```

## Usage

Run the script with administrator/root privileges:

### On Windows:

Run PowerShell or Command Prompt as Administrator

```bash
python network_scanner.py
```
### On Linux/macOS:

```bash
sudo python3 network_scanner.py
```

## Sample Output

```bash
Local IP: 192.168.1.100
Scanning network range: 192.168.1.0/24
Found 5 devices on the network
Network Scan Results:
--------------------------------------------------
Host: router.local
IP Address: 192.168.1.1
MAC Address: aa:bb:cc:dd:ee:ff
Open Ports:
80: HTTP
443: HTTPS
--------------------------------------------------
```


## Known Limitations

- Requires administrator/root privileges for ARP scanning
- May be blocked by firewalls or security software
- Some devices might not respond to ARP requests
- Port scanning might be detected as suspicious activity by security systems

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security Notice

This tool is intended for network administrators and security professionals to scan their own networks. Always obtain proper authorization before scanning any network.