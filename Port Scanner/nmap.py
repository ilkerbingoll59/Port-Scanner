import os
import socket
from concurrent.futures import ThreadPoolExecutor
import time
from threading import Lock

lock = Lock()

def load_ports():
    port_names = {}
    ports = set()
    file_path = os.path.join(os.path.dirname(__file__), "ports.txt")
    
    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue

                name = parts[0]
                last_part = parts[-1]

                if '-' in last_part:
                    try:
                        start_port, end_port = last_part.split('-')
                        start_port = int(start_port)
                        end_port = int(end_port)
                        if start_port <= end_port:
                            for port in range(start_port, end_port + 1):
                                ports.add(port)
                                port_names[port] = name
                    except ValueError:
                        print(f"Invalid port range format: {last_part}")
                else:
                    try:
                        port = int(last_part)
                        ports.add(port)
                        port_names[port] = name
                    except ValueError:
                        print(f"Invalid port number format: {last_part}")
    except FileNotFoundError:
        print(f"{file_path} file not found. Proceeding without port names.")
    return list(ports), port_names

ports, port_names = load_ports()

def scan_port(host, port):
    global global_count
    global prev_glob
    with lock:
        global_count += 1
        curr_glob = global_count * 100 // len(ports)
        if prev_glob < curr_glob:
            print(f"Progress: [{curr_glob}%] {'█' * (curr_glob // 2)}{' ' * (50 - curr_glob // 2)}", end='\r')
            prev_glob = curr_glob

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            return port, True
        else:
            return port, False
    except Exception as e:
        return port, False
    finally:
        sock.close()

def scan_ports(host, ports, threads=1000):
    open_ports = []
    global global_count
    global prev_glob
    prev_glob = 0
    global_count = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda p: scan_port(host, p), ports)
        for port, is_open in results:
            if is_open:
                open_ports.append(port)
    return open_ports

def main():
    ip = ""
    while ip == "":
        host = input("Enter the website (e.g., example.com): ")
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"Bro, this website {host} doesn't exist")

    print(f"Scanning {host} ({ip})...")

    t1 = time.time()
    open_ports = scan_ports(ip, ports)
    t2 = time.time()
    print("\nScan complete!")
    print(f"Ports scanned in {t2 - t1} seconds")

    if open_ports:
        for port in open_ports:
            name = port_names.get(port, "Unknown Service")
            print(f"Open port found: {port} ({name})")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
