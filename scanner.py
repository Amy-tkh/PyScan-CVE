import socket
import requests
import threading

lock = threading.Lock()
report_file = "scan_report.txt"

def write_to_report(data):
    """Write scan results to a report file in a thread-safe manner."""
    with lock:
        with open(report_file, "a") as f:
            f.write(data + "\n")

def check_vulnerabilities(service_info):
    print(f"Checking vulnerabilities for service: {service_info}")
    
    searchquery = " ".join(service_info.split()[:2])
    url = f"https://cve.circl.lu/api/search/{searchquery}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            #We only want the top 3 vulnerabilities for brevity
            vulnerabilities = data.get('data', [])[:3]
            
            if vulnerabilities:
                for vuln in vulnerabilities:
                    print(f" - CVE ID: {vuln.get('id')}")
                    print(f"   Summary: {vuln.get('summary')}")
                    print(f"   Description: {vuln.get('description')}")
                
                else:
                    print("No known vulnerabilities found for this service.") 

    except Exception as e:
        print(f"Error checking vulnerabilities: {e}")
        
def get_banner(s):
    try:
        s.send(b'Hello\r\n')
        banner = s.recv(1024).decode().strip()
        return banner
    except:
        return None

def scan_port(ip, port):
    # Create a socket object
    s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set a timeout for the connection attempt
    s.settimeout(2)
    
    # Try to connect to the specified IP and port
    result = s.connect_ex((ip, port))
    
    # Return the result of the connection attempt
    if result == 0:
        found_masg = f"[+] Port {port} is open on {ip}"
        print(found_masg)
        write_to_report(found_masg)
        
        banner = get_banner(s)
        if banner:
            banner_msg =f"        |_ Service info: {banner}"
            print(banner_msg)
            write_to_report(banner_msg)
            # if banner is found check for vulnerabilities
            check_vulnerabilities(banner)
    
    s.close()
    
target = "scanme.nmap.org"
ports_to_scan = range(1, 1025)  # Common ports range
threads = []

with open(report_file, "w") as f:
    f.write(f"Scan report for {target}\n")


print(f"Scanning {target} for common ports...")

for p in ports_to_scan:
    # Create a new thread for each port scan
    t = threading.Thread(target=scan_port, args=(target, p))
    
    threads.append(t)
    
    t.start()

# Wait for all threads to finish
for t in threads:
    t.join()    
    
print("Scanning completed. Report saved to scan_report.txt")