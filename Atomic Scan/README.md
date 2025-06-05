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
    => SUBDOMAIN ENUMERATION USING CRT.SH and OTX
    => SIMPLE PORT SCANNING
    => BANNER GRABBING
    => WAPPALYZER LOOKUP
                                                                                                                   
                                                                                                               
  To Download it you can use:

    wget https://codeload.github.com/M-Abid34/Atomic-Scanner/zip/refs/heads/main
    git clone https://github.com/M-Abid34/Atomic-Scanner.git
        
  Usage details:

       python3   atomic.py   <domain name>    <flags>

flags Details:

      Usage details: <example.com> flag1  flag2   ......... 

      Flags:  
      --whois     Perform basic WHOIS search
      --dnsenum   for DNS Enumeration
      --crtenum   for Subdomain Enumeration Using CRT.SH API
      --alienenum for Subdomain Enumeration Using OTX API
      --portscan  for Scanning Ports
      --V         for Banner Grabbing
      --W         for Wapplayzer search using Wappalyzer API
Example Usage:

      python3 example.com   --whois --dnsenum --V
