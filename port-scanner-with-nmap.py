import nmap

ip = input("Enter the IP address to scan: ")
begin = input("Enter the starting port: ")
end = input("Enter the ending port: ")


try:
    begin = int(begin)
    end = int(end)
    if begin > end:
        print("Starting port must be less than ending port.")
        exit()
    if begin < 0 or end > 65535:
        print("Port numbers must be between 0 and 65535.")
        exit()
    if not ip or len(ip.split('.')) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip.split('.')):
        print("Invalid IP address format.")
        exit()
except ValueError:
    print("Port values must be integers.")
    exit()


scanner = nmap.PortScanner()

for port in range(begin, end + 1):
    try:
        res = scanner.scan(ip, str(port))
        state = res['scan'][ip]['tcp'][port]['state']
        print(f"Port {port}: {state}")
    except KeyError:
        print(f"Port {port}: No response (possibly closed or filtered)")
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
