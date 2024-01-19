import nmap
scanner = nmap.PortScanner()
print("Welcome, to the Nmap Scanner")
print("Enter the IP Address")
ip_addr = input("IP Address")
print(f"Your IP Address : {ip_addr}")

resp = input("""\n PLease enter the type of scan you want to run
                   1. SYN ACK Scan
                   2. UDP Scan
                   3. Comprehensive Scan
                   \n""")
if resp == '1':
    print("Nmap Version", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("State of your IP address : ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
elif resp == '2' :
    print("Nmap Version", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("State of your IP address : ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("Nmap Version", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("State of your IP address : ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports:", scanner[ip_addr]['tcp'].keys())
elif resp >='4':
    print("Please Enter the Correct Input")
