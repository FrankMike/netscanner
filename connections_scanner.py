import psutil
from datetime import datetime
import socket
from tabulate import tabulate
import sys
import os


def check_permissions():
    if os.name == "posix":  # Unix-like systems (macOS, Linux)
        if os.geteuid() != 0:
            print(
                "Warning: This script requires root privileges to see all connections."
            )
            print("Please run the script with sudo, like this:")
            print("sudo python connections_scanner.py")
            print("\nTrying to continue with limited permissions...\n")


def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "N/A"


def get_connection_status(status):
    status_mapping = {
        psutil.CONN_ESTABLISHED: "ESTABLISHED",
        psutil.CONN_SYN_SENT: "SYN_SENT",
        psutil.CONN_SYN_RECV: "SYN_RECV",
        psutil.CONN_FIN_WAIT1: "FIN_WAIT1",
        psutil.CONN_FIN_WAIT2: "FIN_WAIT2",
        psutil.CONN_TIME_WAIT: "TIME_WAIT",
        psutil.CONN_CLOSE: "CLOSE",
        psutil.CONN_CLOSE_WAIT: "CLOSE_WAIT",
        psutil.CONN_LAST_ACK: "LAST_ACK",
        psutil.CONN_LISTEN: "LISTENING",
        psutil.CONN_NONE: "NONE",
    }
    return status_mapping.get(status, "UNKNOWN")


def scan_connections():
    connections_data = []

    try:
        # Get all network connections
        for conn in psutil.net_connections(kind="inet"):
            try:
                # Get local address details
                local_ip, local_port = conn.laddr if conn.laddr else ("", "")

                # Get remote address details
                if conn.raddr:
                    remote_ip, remote_port = conn.raddr
                    try:
                        remote_host = socket.gethostbyaddr(remote_ip)[0]
                    except socket.herror:
                        remote_host = "Unknown"
                else:
                    remote_ip, remote_port = "", ""
                    remote_host = ""

                # Get process details
                process_name = get_process_name(conn.pid) if conn.pid else "N/A"

                # Add connection information to the list
                connections_data.append(
                    [
                        process_name,
                        f"{local_ip}:{local_port}",
                        f"{remote_ip}:{remote_port}",
                        remote_host,
                        get_connection_status(conn.status),
                        conn.pid or "N/A",
                    ]
                )

            except (socket.error, psutil.Error):
                continue
    except psutil.AccessDenied:
        print("Error: Access denied when trying to get network connections.")
        print("This is likely because the script needs elevated privileges.")
        if os.name == "posix":
            print("\nPlease run the script with sudo:")
            print("sudo python connections_scanner.py")
        sys.exit(1)

    return connections_data


def main():
    print(
        f"\nNetwork Connections Scanner - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )

    check_permissions()
    connections = scan_connections()

    if not connections:
        print("No connections found or unable to access connection information.")
        return

    # Prepare table headers
    headers = [
        "Process",
        "Local Address",
        "Remote Address",
        "Remote Host",
        "Status",
        "PID",
    ]

    # Print the connections table
    print(tabulate(connections, headers=headers, tablefmt="grid"))
    print(f"\nTotal connections found: {len(connections)}")


if __name__ == "__main__":
    main()
