import nmap

def is_valid_ip(ip):
    parts = ip.split(".")
    return (
        len(parts) == 4 and
        all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    )

def get_input():
    ip = input("Enter the IP address to scan: ").strip()
    if not ip or not is_valid_ip(ip):
        print("Invalid IP address format.")
        exit()

    try:
        begin = int(input("Enter the starting port: "))
        end = int(input("Enter the ending port: "))
    except ValueError:
        print("Port values must be integers.")
        exit()

    if begin < 0 or end > 65535 or begin > end:
        print("Port range must be 0–65535 and starting port must be <= ending port.")
        exit()

    return ip, begin, end

def scan_ports(ip, start, end):
    scanner = nmap.PortScanner()

    for port in range(start, end + 1):
        try:
            result = scanner.scan(ip, str(port))
            state = result['scan'][ip]['tcp'][port]['state']
            print(f"Port {port}: {state}")
        except KeyError:
            print(f"Port {port}: No response (likely closed or filtered)")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

if __name__ == "__main__":
    ip, begin, end = get_input()
    scan_ports(ip, begin, end)
