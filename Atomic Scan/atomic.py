import requests
from Wappalyzer import Wappalyzer , WebPage
from datetime import datetime
import sys
import dns.resolver
import whois
import socket

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
    except:
        print(f"Error Performing Whois!.")


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
            Subdomains = sub.get('name_value','').split('\n')
            for name in Subdomains:
                if name.endswith(domain):
                    subdomains.add(name.strip())
        report(sorted(subdomains))
        return sorted(subdomains)
    except Exception as e:
        print("Error")



def check_port_status(ip,port:int) -> bool:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip,port))
            return True
        except ConnectionRefusedError:
            return False
        except socket.timeout:
            return False



def nmap(ip):
    report(f" PORT SCANNING FOR {ip}")
    start = int(input("Enter the starting Port: "))
    if start < 1:
        start = 1
    end = int(input("Enter the Ending Port: "))
    if end < 1 or end > 65535:
        end = 65535
    for port in range(start,end+1,1):
        response = check_port_status(ip,port)
        if response:
            print(f"Port {port} is Open.")
            report(f"Port {port} is Open.")
        else:
            continue
    
def bannergrabber(ip):
    report(f" BANNER GRABBING FOR {ip}")
    start = int(input("Enter the starting port: "))
    end = int(input("Enter the ending port: "))
    if start < 1:
        start = 1
    if end < 1 or end > 65535:
        end = 65535

    for port in range(start, end + 1):
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))

            if port == 80:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode())
            elif port == 21:
                s.sendall(b"SYST\r\n")
            elif port == 25:
                s.sendall(b"EHLO example.com\r\n")
            # can be customized further as per requirements
            banner = s.recv(1024)
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"

            print(f"[+] Port {port} ({service}): {banner.decode(errors='ignore').strip()}")
            report(f"[+] Port {port} ({service}): {banner.decode(errors='ignore').strip()}")
            s.close()

        except Exception as e:
            # print(f"[-] Port {port} closed or no banner. ({str(e)})")  Uncomment only For debugging 
            pass


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
    except Exception:
        print("Faild To Analyze the Technologies.")


def report(result):
    with open("Report.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {result}", file=f)

def directoryenumeration(domain,wordlist):
    report(f"Directory Enumeration for {domain}")
    url = f"http://{domain}/"
    with open(wordlist, 'r') as file:
        for line in file:
            directory = line.strip()
            full_url = url + directory
            try:
                response = requests.get(full_url, timeout=5)
                if response.status_code == 200:
                    print(f"Found: {full_url}")
                    report(f"Found: {full_url}")
                elif response.status_code == 403:
                    print(f"[-] Forbidden: {full_url} (Status: 403)")
                elif response.status_code == 404:
                    print(f"[-] Not Found: {full_url} (Status: 404)")
                elif response.status_code == 500:
                    print(f"[-] Internal Server Error: {full_url} (Status: 500)")
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
        ip = socket.gethostbyname(domain)
        print(nmap(ip))
        print("Completed.")
    if "--V" in flag:
        print("Starting  Banner Grabbing ............")
        ip = socket.gethostbyname(domain)
        print(bannergrabber(ip))
        print("Completed.")
    if "--W" in flag:
        print("Starting  Wapplyzer API Lookup ............")
        print(wappalyzer(domain))
        print("Completed.")
    if "--direnum" in flag:
        print("Starting Directory Enumeration ............")
        wordlist = input("Enter the path to the wordlist file: ")
        directoryenumeration(domain, wordlist)
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
        ip = socket.gethostbyname(domain)
        print(nmap(ip))
        print("Completed.\n")
        print("Starting  Banner Grabbing ............")
        ip = socket.gethostbyname(domain)
        print(bannergrabber(ip))
        print("Completed.\n")
        print("Starting  Wapplyzer API Lookup ............")
        print(wappalyzer(domain))
        print("Completed.\n")
        print("Starting Directory Enumeration ............")
        wordlist = input("Enter the path to the wordlist file: ")
        directoryenumeration(domain, wordlist)
        print("Completed.\n")
        print("All operations completed successfully.")
        print("Report saved to Report.txt")





# This code is a modular recon toolkit that can perform various reconnaissance tasks such as WHOIS lookup, DNS enumeration, subdomain enumeration using crt.sh, port scanning, banner grabbing, Wappalyzer lookup, and directory enumeration.
# It provides a command-line interface for users to specify the target domain and the desired operations to perform. The results of each operation are printed to the console and saved to a report file named "Report.txt".