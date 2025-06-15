import requests
from Wappalyzer import Wappalyzer , WebPage
from datetime import datetime
import sys
import dns.resolver
import whois
import socket
from concurrent.futures import ThreadPoolExecutor
import time
import subprocess
import re
open_ports = []    
banners = {}
def print_banner():
    banner = r"""
     █████╗ ████████╗ ██████╗ ███╗   ███╗██╗ ██████╗     ███████╗  ██████╗  █████╗ ███╗   ██╗
    ██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║██║██╔════╝     ██╔════╝ ██╔════╝ ██╔══██╗████╗  ██║
    ███████║   ██║   ██║   ██║██╔████╔██║██║██║          ███████║ ██║      ███████║██╔██╗ ██║
    ██╔══██║   ██║   ██║   ██║██║╚██╔╝██║██║██║   ██║    ╔══╝  ██ ██║   ██║██╔══██║██║╚██╗██║
    ██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║╚██████╔╝    ███████╗╚ ██████╔╝██║  ██║██║ ╚████║
    ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝ ╚═════╝      ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

                               ⚡ Fast • Modular • Recon Toolkit ⚡
    Which can perfome:
    => WHOIS LOOKUP
    => DNS ENUMERATION
    => SUBDOMAIN ENUMERATION USING CRT.SH 
    => SIMPLE PORT SCANNING
    => BANNER GRABBING
    => WAPPALYZER LOOKUP
    => Sub Direcotry Enumeration
    
    """
    print(banner)

def funcwhois(domain):
    try:
        report(f"WHOIS LookUP FOR {domain}")
        info = whois.whois(domain)
        report(info)
        return info
    except Exception as e:
        report(f"Error Performing Whois LookUP for {domain}: {e}")
        print(f"Error Performing Whois!: {e}")
        return None

def funcdnsenum(domain):
    try:
        report(f"DNS ENUMERATION FOR {domain}")
        resultA = dns.resolver.resolve(domain,'A')
        print("IP Address for Domain: ")
        for ip in resultA:
            print(ip.to_text())
            report(ip.to_text())
        resultB = dns.resolver.resolve(domain,'MX')
        print("MX Record for Domain: ")
        for ip in resultB:
            print(ip.to_text())
            report(ip.to_text())
        resultC = dns.resolver.resolve(domain,'TXT')
        print("TXT Record  for Domain: ")
        for ip in resultC:
            print(ip.to_text())
            report(ip.to_text())
        resultD = dns.resolver.resolve(domain,'NS')
        print("NS Records for Domain: ")
        for ip in resultD:
            print(ip.to_text())
            report(ip.to_text())
    except:
        report(f"Error Performing DNS ENUMERATION for {domain}")
        print(f"Error Performing DNS ENUMERATION!")




        
def funccrtenum(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        report(f"CRT.SH ENUMERATION FOR {domain}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()  
        data = response.json()
        
        subdomains = set()
        for sub in data:
            entries = sub.get('name_value', '').split('\n')
            for name in entries:
                if name.endswith(domain):
                    subdomains.add(name.strip())

        sorted_subs = sorted(subdomains)
        report(sorted_subs)
        return sorted_subs

    except Exception as e:
        report(f"Error Performing CRT.SH ENUMERATION for {domain}: {str(e)}")
        print(f"Error: {str(e)}")
        return []


def load_ports(ports):
    with open('nmap-top-ports.txt','r') as f:
        for line in f:
            p = int(line.strip())
            ports.append(p)
        return ports
    

def port_scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(f"[+] port {port} is open")
            open_ports.append(port)
    except KeyboardInterrupt:
        report(f"Port scanning interrupted for {target_ip}")
        print("\n Exiting Program !!!!")
        sys.exit()
    except:
        return False
    

def run_scanner(ports, thread_count = 100):
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        for port in ports:
            executor.submit(port_scan, port)
def run_scanner_banner(ports, thread_count = 100):
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        for port in ports:
            executor.submit(banner_grab, port)
    
def banner_grab(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            try:
                time.sleep(0.5)
                if port == 80:
                    http_req = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                    s.sendall(http_req.encode())
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                elif port == 22 or port == 21 or port == 25:
                    time.sleep(0.5)
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                else:
                    time.sleep(0.5)
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            except Exception:
                banner = ''
            print(f"[+] Port {port} is open | Banner: {banner if banner else 'No banner received'}")
            open_ports.append(port)
            banners[port] = banner if banner else 'No banner received'
        s.close()
    except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()
    except Exception as e:
        return False

def wappalyzer(domain):
    report(f"WAPPALYZER FOR {domain}")
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "https://" + domain
    try:
        webpage = WebPage.new_from_url(domain)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
        print("Results:")
        for technology, explanation in technologies.items():
            print(f"=> {technology}: {explanation}")
        report(technologies)
        return technologies
    except Exception as e:
        print("Failed To Analyze the Technologies.")
        report(f"[!] Failed To Analyze the Technologies: {str(e)}")


def run_tech_detect(domain):
    report(f"TECHNOLOGY DETECTION FOR {domain}")
    try:
        result = subprocess.check_output(
            ["whatweb", domain],
            stderr=subprocess.STDOUT,
            timeout=10
        )
        print("WhatWeb Results:")
        print(result.decode().strip())
        report(result.decode().strip())
    except subprocess.TimeoutExpired:
        report(f"[!] Technology detection timed out for {domain}")
        return "[!] Technology detection timed out."
    except subprocess.CalledProcessError as e:
        report(f"[!] WhatWeb error:\n{e.output.decode().strip()}")
        return f"[!] WhatWeb error:\n{e.output.decode().strip()}"
    except Exception as e:
        report(f"[!] Tech detection failed: {str(e)}")
        return f"[!] Tech detection failed: {str(e)}"
def clean_banner(text):
    return re.sub(r'[^\x20-\x7E]', '.', text)  

def report(result):
    with open("Report.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {result}", file=f)

def directoryenumeration(domain, wordlist):
    report(f"Directory Enumeration for {domain}")

    protocols = ['https://', 'http://']
    for proto in protocols:
        url = proto + domain + '/'
        try:
            requests.get(url, timeout=5)
            break  # If this works, use it
        except requests.RequestException:
            continue
    else:
        print(f"[!] Could not connect to {domain} using HTTP or HTTPS.")
        return

    with open(wordlist, 'r') as file:
        for line in file:
            directory = line.strip()
            full_url = url + directory
            try:
                response = requests.get(full_url, timeout=5)
                if response.status_code == 200:
                    print(f"[+] Found: {full_url}")
                    report(f"[+] Found: {full_url}")
                elif response.status_code == 403:
                    print(f"[-] Forbidden: {full_url} (403)")
                elif response.status_code == 404:
                    pass  # Silent skip or log
                elif response.status_code == 500:
                    print(f"[!] Server Error: {full_url} (500)")
            except requests.RequestException:
                continue

if __name__ == "__main__":
    print_banner()
    if len(sys.argv) <2:
        print(f"""Usage details: <example.com> flag1  flag2   ......... 
              
    Flags:  
        --whois     Perform basic WHOIS search
        --dnsenum   for DNS Enumeration
        --crtenum   for Subdomain Enumeration Using CRT.SH API
        --direnum   for Directory Enumeration 
        --portscan  for Scanning Ports
        --V         for Banner Grabbing
        --W         for Wapplayzer search using Wappalyzer API
        --what      for Technology Detection using WhatWeb
        --all       for All the above operations
        """)
        sys.exit(1)
    
    domain = sys.argv[1]
    flag = sys.argv[2:]

    if len(flag) < 1:
        print(f"Please input a Flag to Process")
        sys.exit(1)

    if "--whois" in flag:
        print("Starting WHOIS............")
        print(funcwhois(domain))
        print("Completed.")
    if "--dnsenum" in flag:
        print("Starting DNS ENUMERATION............")
        print(funcdnsenum(domain))
        print("Completed.")
    if "--crtenum" in flag:
        print("Starting  CRT SUBDOMAIN ENUMERATION............")
        print(funccrtenum(domain))
        print("Completed.")
    if "--portscan" in flag:
        print("Starting  Port Scanning ............")
        start = time.time()
        global target_ip
        target_ip = socket.gethostbyname(domain)
        ports = []
        load_ports(ports)
        print('Starting scan on host:', target_ip)
        run_scanner(ports)
        end = time.time()
        print(f'time taken {end - start:.2f} seconds')
        print(f"Open ports found: {sorted(open_ports)}")
        report(f"Port Scanning for {domain} completed in {end - start:.2f} seconds. Open ports: {sorted(open_ports)}")
        print("Completed.")
    if "--V" in flag:
        print("Starting  Banner Grabbing ............")
        start = time.time()
        target_ip = socket.gethostbyname(domain)
        ports = []
        load_ports(ports)
        print('Starting banner grabbing on host:', target_ip)
        run_scanner_banner(ports)
        end = time.time()
        print(f'Time taken: {end - start:.2f} seconds')
        print(f"Open ports with banners:")
        for port in sorted(open_ports):
            print(f"  {port}: {banners[port] if banners[port] else 'No banner received'}")
        report(f"Banner Grabbing for {domain} completed in {end - start:.2f} seconds. Open ports with banners: {banners}")
        print("Completed.")
    if "--W" in flag:
        print("Starting  Wapplyzer API Lookup ............")
        print(wappalyzer(domain))
        print("Completed.")
    if "--direnum" in flag:
        print("Starting Directory Enumeration ............")
        wordlist = 'directory.txt'
        directoryenumeration(domain, wordlist)
        print("Completed.")
    if "--what" in flag:
        print("Performing WhatWeb ............")
        run_tech_detect(domain)
        print("Completed.")
    if "--all" in flag:
        print("Starting WHOIS............")
        print(funcwhois(domain))
        print("Completed.\n")
        print("Starting DNS ENUMERATION............")
        print(funcdnsenum(domain))
        print("Completed.\n")
        print("Starting  CRT SUBDOMAIN ENUMERATION............")
        print(funccrtenum(domain))
        print("Completed.\n")
        print("Starting  Port Scanning ............")
        start = time.time()
        target_ip = socket.gethostbyname(domain)
        ports = []
        load_ports(ports)
        print('Starting scan on host:', target_ip)
        run_scanner(ports)
        end = time.time()
        print(f'time taken {end - start:.2f} seconds')
        print(f"Open ports found: {sorted(open_ports)}")
        report(f"Port Scanning for {domain} completed in {end - start:.2f} seconds. Open ports: {sorted(open_ports)}")
        print("Completed.\n")
        print("Starting  Banner Grabbing ............")
        start = time.time()
        target_ip = socket.gethostbyname(domain)
        ports = []
        load_ports(ports)
        print('Starting banner grabbing on host:', target_ip)
        run_scanner_banner(ports)
        end = time.time()
        print(f'Time taken: {end - start:.2f} seconds')
        print(f"Open ports with banners:")
        report(f"Banner Grabbing for {domain} completed in {end - start:.2f} seconds. Open ports with banners: {banners}")
        print("Completed.\n")
        print("Starting  Wapplyzer API Lookup ............")
        print(wappalyzer(domain))
        print("Completed.\n")
        print("Performing WhatWeb ............")
        run_tech_detect(domain)
        print("Completed.\n")
        print("Starting Directory Enumeration ............")
        wordlist = 'directory.txt'
        directoryenumeration(domain, wordlist)
        print("Completed.\n")
        print("All operations completed successfully.")
        print("Report saved to Report.txt")





# This code is a modular recon toolkit that can perform various reconnaissance tasks such as WHOIS lookup, DNS enumeration, subdomain enumeration using crt.sh, port scanning, banner grabbing, Wappalyzer lookup, and directory enumeration.
# It provides a command-line interface for users to specify the target domain and the desired operations to perform. The results of each operation are printed to the console and saved to a report file named "Report.txt".