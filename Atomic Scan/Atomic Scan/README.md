Hello All ,   This is Project Based Educational Tool only Developed for Educational Purpose.



With all things like Domain Enumeration , port Scanning whether its  WHOIS Lookup or its Banner Grabbing; Using a different Tool for Each time is quite irritating.

For the solution We introduce you to :

                    █████╗ ████████╗ ██████╗ ███╗   ███╗██╗ ██████╗     ███████╗  ██████╗  █████╗ ███╗   ██╗
                   ██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║██║██╔════╝     ██╔════╝ ██╔════╝ ██╔══██╗████╗  ██║
                   ███████║   ██║   ██║   ██║██╔████╔██║██║██║          ███████║ ██║      ███████║██╔██╗ ██║
                   ██╔══██║   ██║   ██║   ██║██║╚██╔╝██║██║██║   ██║    ╔══╝  ██ ██║   ██║██╔══██║██║╚██╗██║
                   ██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║╚██████╔╝    ███████╗╚ ██████╔╝██║  ██║██║ ╚████║
                   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝ ╚═════╝      ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
               
                                              ⚡ Fast • Modular • Recon Toolkit ⚡
    Which can perfomr:
    => WHOIS LOOKUP
    => DNS ENUMERATION
    => SUBDOMAIN ENUMERATION USING CRT.SH 
    => SIMPLE PORT SCANNING
    => BANNER GRABBING
    => WAPPALYZER LOOKUP
    => Sub Directory Enumeration
                                                                                                                   
                                                                                                               
  To Download it you can use:

    wget https://codeload.github.com/M-Abid34/Atomic-Scanner/zip/refs/heads/main
    git clone https://github.com/M-Abid34/Atomic-Scanner.git
    
  Dependencis:
    
  incase if kali is not installing packages directly use virtual environment
    
    python3 -m venv myenv 
    source myenv/bin/activate

Then install the dependencies:

    pip install python-Wappalyzer
    pip install dnspython
    pip install python-whois
    pip install setuptools
    pip install requests
    pip install pyppeteer

nmap-top-ports.txt is a must file in the same folder as program for operation and also the directory.txt.
if you want to put your own directory name file just copy the names in the file or paste the file in the same folder as programe and change the file name in the code

  
  Usage details:

       python3   atomic.py   <domain name>    <flags>

flags Details:

      Usage details: <example.com> flag1  flag2   ......... 

      Flags:  
      --whois     Perform basic WHOIS search
      --dnsenum   for DNS Enumeration
      --crtenum   for Subdomain Enumeration Using CRT.SH API
      --direnum   for Subdirectories Enumeration 
      --portscan  for Scanning Ports
      --V         for Banner Grabbing
      --W         for Wapplayzer search using Wappalyzer API
      --what      for performing whatweb
      --all       for all of the above
Example Usage:

      python3 example.com   --whois --dnsenum --V
