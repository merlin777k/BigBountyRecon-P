#!/usr/bin/env python3
'''
BigBountyRecon - Python Recon Tool for Bug Bounty Hunters

A Python implementation similar to the original BigBountyRecon, automating
reconnaissance processes during bug bounty hunting by integrating various
online tools in one place.
'''

import os
import sys
import webbrowser
import argparse
import urllib.parse
import time
import random
import json
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class BigBountyRecon:
    def __init__(self):
        self.banner = f'''
{Fore.RED}
 ____  _       ____                  _       ____                      
| __ )(_) __ _| __ )  ___  _   _ ___| |_ _  |  _ \\ ___  ___ ___  _ __  
|  _ \\| |/ _` |  _ \\ / _ \\| | | / __| __| | | |_) / _ \\/ __/ _ \\| '_ \\ 
| |_) | | (_| | |_) | (_) | |_| \\__ \\ |_| | |  _ <  __/ (_| (_) | | | |
|____/|_|\\__, |____/ \\___/ \\__,_|___/\\__|_| |_| \\_\\___|\\___\\___/|_| |_|
        |___/                                                         
{Style.RESET_ALL}
    {Fore.YELLOW}    >>> Python Bug Bounty Recon Tool <<<{Style.RESET_ALL}
    {Fore.CYAN}    >>> Created by [Your Name] ({Fore.GREEN}Python Version{Style.RESET_ALL}{Fore.CYAN}){Style.RESET_ALL}
    '''
        
        self.categories = {
            "all": "Run all the tools",
            "subdomain-enum": "Tools for subdomain enumeration", 
            "subdomain-takeover": "Tools for subdomain takeover",
            "port-scanning": "Tools for port scanning",
            "screenshots": "Tools for website screenshots",
            "url-extraction": "URL extraction tools",
            "js-hunting": "Tools for JavaScript hunting",
            "content-discovery": "Content discovery tools",
            "parameter-discovery": "Parameter discovery tools",
            "ip-info": "IP information tools",
            "cors-misconfiguration": "CORS misconfiguration tools",
            "s3-buckets": "S3 bucket tools",
            "dns-info": "DNS information tools",
            "directory-fuzzing": "Directory fuzzing tools",
            "visual-recon": "Visual recon tools",
            "tech-stack": "Tech stack detection tools",
            "file-analysis": "File analysis tools",
            "github-dorks": "GitHub dorks tools",
            "wayback-machine": "Wayback machine tools",
            "nuclei-templates": "Nuclei templates tools",
            "fuzzing": "Fuzzing tools",
            "cms-scanners": "CMS scanner tools",
            "wordlists": "Wordlist resources",
            "other-tools": "Other useful tools"
        }
        
        # Online recon tools URLs
        self.tools = self._load_tools()
        
    def _load_tools(self):
        """Load all reconnaissance tools"""
        return {
            "subdomain-enum": {
                "Sublist3r": "https://dnsdumpster.com/",
                "Amass": "https://github.com/OWASP/Amass",
                "Subfinder": "https://github.com/projectdiscovery/subfinder",
                "Assetfinder": "https://github.com/tomnomnom/assetfinder",
                "Findomain": "https://github.com/Findomain/Findomain",
                "Crt.sh": "https://crt.sh/?q={domain}",
                "SecurityTrails": "https://securitytrails.com/list/apex_domain/{domain}",
                "RapidDNS": "https://rapiddns.io/subdomain/{domain}",
                "BufferOver": "https://dns.bufferover.run/dns?q={domain}",
                "Shodan": "https://www.shodan.io/search?query={domain}",
                "AlienVault": "https://otx.alienvault.com/browse/global/indicators",
                "VirusTotal": "https://www.virustotal.com/gui/domain/{domain}/relations",
                "HackerTarget": "https://hackertarget.com/find-dns-host-records/",
                "ThreatCrowd": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
                "Entrust": "https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain={domain}&includeExpired=true&exactMatch=false&limit=5000",
                "GoogleTransparency": "https://transparencyreport.google.com/https/certificates?hl=en&cert_search_auth=&cert_search_cert=&cert_search=include_expired:true;include_subdomains:true;domain:{domain}&lu=cert_search",
            },
            "subdomain-takeover": {
                "Subjack": "https://github.com/haccer/subjack",
                "Subover": "https://github.com/Ice3man543/SubOver",
                "SubTko": "https://github.com/xrooters/SubTko",
                "TakeOver": "https://github.com/m4ll0k/takeover",
                "Can-I-Take-Over-XYZ": "https://github.com/EdOverflow/can-i-take-over-xyz",
            },
            "port-scanning": {
                "Nmap Online": "https://nmap.online/",
                "Shodan": "https://www.shodan.io/search?query={domain}",
                "Censys": "https://censys.io/ipv4?q={domain}",
                "HackerTarget": "https://hackertarget.com/nmap-online-port-scanner/",
                "PortCheckTool": "https://www.portchecktool.com/",
                "Spiderip": "https://spiderip.com/online-port-scan.php",
                "YouGetSignal": "https://www.yougetsignal.com/tools/open-ports/",
                "Netlas": "https://app.netlas.io/responses/?q=host%3A{domain}",
            },
            "screenshots": {
                "Eyewitness": "https://github.com/FortyNorthSecurity/EyeWitness",
                "Aquatone": "https://github.com/michenriksen/aquatone",
                "HttpScreenshot": "https://github.com/breenmachine/httpscreenshot",
                "Webscreenshot": "https://github.com/maaaaz/webscreenshot",
                "VisualSiteMapper": "http://www.visualsitemapper.com/map/{domain}",
                "Screenshoteer": "https://github.com/vladocar/screenshoteer",
            },
            "url-extraction": {
                "Waybackurls": "https://github.com/tomnomnom/waybackurls",
                "Gau": "https://github.com/lc/gau",
                "Hakrawler": "https://github.com/hakluke/hakrawler",
                "Paramspider": "https://github.com/devanshbatham/ParamSpider",
                "Gospider": "https://github.com/jaeles-project/gospider",
                "Katana": "https://github.com/projectdiscovery/katana",
            },
            "js-hunting": {
                "LinkFinder": "https://github.com/GerbenJavado/LinkFinder",
                "SecretFinder": "https://github.com/m4ll0k/SecretFinder",
                "JsScanner": "https://github.com/dark-warlord14/JSScanner",
                "JSFScan": "https://github.com/KathanP19/JSFScan.sh",
                "RetireJS": "https://retirejs.github.io/retire.js/",
                "JSParser": "https://github.com/nahamsec/JSParser",
            },
            "content-discovery": {
                "Dirsearch": "https://github.com/maurosoria/dirsearch",
                "Gobuster": "https://github.com/OJ/gobuster",
                "Feroxbuster": "https://github.com/epi052/feroxbuster",
                "GoBusterDir": "https://github.com/OJ/gobuster",
                "DirBuster": "https://gitlab.com/kalilinux/packages/dirbuster",
                "WordPressScanner": "https://github.com/wpscanteam/wpscan",
                "Photon": "https://github.com/s0md3v/Photon",
            },
            "parameter-discovery": {
                "Arjun": "https://github.com/s0md3v/Arjun",
                "ParamSpider": "https://github.com/devanshbatham/ParamSpider",
                "ParamMiner": "https://github.com/PortSwigger/param-miner",
                "x8": "https://github.com/Sh1Yo/x8",
                "Parameth": "https://github.com/maK-/parameth",
            },
            "ip-info": {
                "IPinfo": "https://ipinfo.io/{ip}",
                "Shodan": "https://www.shodan.io/host/{ip}",
                "Censys": "https://censys.io/ipv4/{ip}",
                "AbuseIPDB": "https://www.abuseipdb.com/check/{ip}",
                "MaxMind": "https://www.maxmind.com/en/geoip-demo",
                "Greynoise": "https://viz.greynoise.io/ip/{ip}",
            },
            "cors-misconfiguration": {
                "CORScanner": "https://github.com/chenjj/CORScanner",
                "CORStest": "https://github.com/RUB-NDS/CORStest",
                "Corsy": "https://github.com/s0md3v/Corsy",
                "CORSy": "https://github.com/JacksonGL/cors-exploitation-demo",
            },
            "s3-buckets": {
                "S3Scanner": "https://github.com/sa7mon/S3Scanner",
                "AWSBucketDump": "https://github.com/jordanpotti/AWSBucketDump",
                "S3Inspector": "https://github.com/clario-tech/s3-inspector",
                "Bucket Finder": "https://github.com/FishermansEnemy/bucket_finder",
                "S3 Bucket Finder": "https://github.com/gwen001/s3-buckets-finder",
            },
            "dns-info": {
                "Dnsdumpster": "https://dnsdumpster.com/",
                "SecurityTrails": "https://securitytrails.com/domain/{domain}/dns",
                "ViewDNS": "https://viewdns.info/",
                "MXToolbox": "https://mxtoolbox.com/SuperTool.aspx?action=dns%3a{domain}&run=toolpage",
                "IntoDNS": "https://intodns.com/{domain}",
                "DNSlytics": "https://dnslytics.com/domain/{domain}",
            },
            "directory-fuzzing": {
                "Dirsearch": "https://github.com/maurosoria/dirsearch",
                "Gobuster": "https://github.com/OJ/gobuster",
                "Wfuzz": "https://github.com/xmendez/wfuzz",
                "DirBuster": "https://gitlab.com/kalilinux/packages/dirbuster",
                "Feroxbuster": "https://github.com/epi052/feroxbuster",
            },
            "visual-recon": {
                "SpiderFoot": "https://www.spiderfoot.net/",
                "ReconNG": "https://github.com/lanmaster53/recon-ng",
                "Maltego": "https://www.maltego.com/",
                "WebMap": "https://github.com/webhackinc/webmap",
                "BBHT": "https://github.com/nahamsec/bbht",
            },
            "tech-stack": {
                "Wappalyzer": "https://www.wappalyzer.com/lookup/{domain}/",
                "Netcraft": "https://sitereport.netcraft.com/?url={domain}",
                "BuiltWith": "https://builtwith.com/{domain}",
                "WhatRuns": "https://www.whatruns.com/",
                "Shodan": "https://www.shodan.io/search?query={domain}",
                "Censys": "https://censys.io/domain?q={domain}",
            },
            "file-analysis": {
                "Retire.js": "https://github.com/RetireJS/retire.js",
                "JSParser": "https://github.com/nahamsec/JSParser",
                "LinkFinder": "https://github.com/GerbenJavado/LinkFinder",
                "SecretFinder": "https://github.com/m4ll0k/SecretFinder",
            },
            "github-dorks": {
                "TruffleHog": "https://github.com/trufflesecurity/truffleHog",
                "GitRob": "https://github.com/michenriksen/gitrob",
                "GitLeaks": "https://github.com/zricethezav/gitleaks",
                "GitHound": "https://github.com/tillson/git-hound",
                "GitDorker": "https://github.com/obheda12/GitDorker",
                "Github-Dorks": "https://github.com/techgaun/github-dorks",
            },
            "wayback-machine": {
                "WaybackMachine": "https://web.archive.org/web/*/{domain}",
                "WaybackUrls": "https://github.com/tomnomnom/waybackurls",
                "GAU": "https://github.com/lc/gau",
            },
            "nuclei-templates": {
                "NucleiTemplates": "https://github.com/projectdiscovery/nuclei-templates",
                "CVETracker": "https://github.com/projectdiscovery/nuclei-templates/tree/master/cves",
                "Vulns": "https://github.com/projectdiscovery/nuclei-templates/tree/master/vulnerabilities",
            },
            "fuzzing": {
                "FFuF": "https://github.com/ffuf/ffuf",
                "Wfuzz": "https://github.com/xmendez/wfuzz",
                "Gobuster": "https://github.com/OJ/gobuster",
                "Dirsearch": "https://github.com/maurosoria/dirsearch",
                "Feroxbuster": "https://github.com/epi052/feroxbuster",
            },
            "cms-scanners": {
                "WPScan": "https://wpscan.com/search?text={domain}",
                "Joomscan": "https://github.com/OWASP/joomscan",
                "Droopescan": "https://github.com/droope/droopescan",
                "CMSeeK": "https://github.com/Tuhinshubhra/CMSeeK",
                "CMSmap": "https://github.com/Dionach/CMSmap",
            },
            "wordlists": {
                "SecLists": "https://github.com/danielmiessler/SecLists",
                "Assetnote": "https://wordlists.assetnote.io/",
                "FuzzDB": "https://github.com/fuzzdb-project/fuzzdb",
                "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings",
                "BruteForce-Lists": "https://github.com/random-robbie/bruteforce-lists",
            },
            "other-tools": {
                "HTTPX": "https://github.com/projectdiscovery/httpx",
                "Altdns": "https://github.com/infosec-au/altdns",
                "MassDNS": "https://github.com/blechschmidt/massdns",
                "Dalfox": "https://github.com/hahwul/dalfox",
                "Nuclei": "https://github.com/projectdiscovery/nuclei",
                "Amass": "https://github.com/OWASP/Amass",
            }
        }
    
    def print_banner(self):
        """Print tool banner"""
        print(self.banner)
    
    def print_usage(self):
        """Print usage information"""
        print(f"{Fore.CYAN}Usage:{Style.RESET_ALL}")
        print(f"  python3 {os.path.basename(__file__)} -d example.com -c subdomain-enum")
        print(f"  python3 {os.path.basename(__file__)} --domain example.com --category all")
        print(f"  python3 {os.path.basename(__file__)} --list-categories\n")
        
        print(f"{Fore.CYAN}Options:{Style.RESET_ALL}")
        print(f"  -d, --domain DOMAIN        Target domain to recon")
        print(f"  -c, --category CATEGORY    Category of recon tools to use")
        print(f"  -l, --list-categories      List all available categories")
        print(f"  -h, --help                 Show this help message and exit\n")
    
    def list_categories(self):
        """List all available tool categories"""
        print(f"\n{Fore.CYAN}Available Categories:{Style.RESET_ALL}")
        
        # Calculate the maximum category name length for better formatting
        max_len = max(len(cat) for cat in self.categories.keys())
        
        for category, description in self.categories.items():
            print(f"  {Fore.GREEN}{category.ljust(max_len)}{Style.RESET_ALL} : {description}")
        print()
    
    def open_tool(self, tool_name, tool_url, domain):
        """Open a specific tool in the browser"""
        try:
            # Replace placeholders with the actual domain
            url = tool_url.replace("{domain}", domain).replace("{ip}", domain)
            
            print(f"  {Fore.BLUE}[+]{Style.RESET_ALL} Opening {Fore.YELLOW}{tool_name}{Style.RESET_ALL} at {url}")
            webbrowser.open(url)
            
            # Add a small delay to avoid overwhelming the browser
            time.sleep(random.uniform(0.5, 1.5))
            
            return True
        except Exception as e:
            print(f"  {Fore.RED}[!]{Style.RESET_ALL} Error opening {tool_name}: {str(e)}")
            return False
    
    def run_category(self, domain, category):
        """Run all tools in a specific category"""
        if category not in self.tools and category != "all":
            print(f"{Fore.RED}[!] Invalid category: {category}{Style.RESET_ALL}")
            self.list_categories()
            return False
        
        if category == "all":
            print(f"\n{Fore.GREEN}[*] Running all reconnaissance tools for domain: {domain}{Style.RESET_ALL}")
            
            for cat_name, tools in self.tools.items():
                print(f"\n{Fore.CYAN}[+] Category: {cat_name.upper()}{Style.RESET_ALL}")
                
                for tool_name, tool_url in tools.items():
                    # Skip tools that don't have direct URLs
                    if "github.com" in tool_url and "{domain}" not in tool_url:
                        print(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} {tool_name}: {tool_url} (GitHub project)")
                        continue
                    
                    # Skip tools without domain parameter
                    if "{domain}" not in tool_url and "{ip}" not in tool_url:
                        print(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} {tool_name}: {tool_url} (No domain parameter)")
                        continue
                    
                    self.open_tool(tool_name, tool_url, domain)
        else:
            print(f"\n{Fore.GREEN}[*] Running {category} tools for domain: {domain}{Style.RESET_ALL}")
            
            for tool_name, tool_url in self.tools[category].items():
                # Skip tools that don't have direct URLs
                if "github.com" in tool_url and "{domain}" not in tool_url:
                    print(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} {tool_name}: {tool_url} (GitHub project)")
                    continue
                
                # Skip tools without domain parameter
                if "{domain}" not in tool_url and "{ip}" not in tool_url:
                    print(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} {tool_name}: {tool_url} (No domain parameter)")
                    continue
                
                self.open_tool(tool_name, tool_url, domain)
        
        return True
        
    def export_tools(self, filename="recon_tools.json"):
        """Export all tools to a JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.tools, f, indent=4)
            print(f"{Fore.GREEN}[+] Tools exported to {filename}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error exporting tools: {str(e)}{Style.RESET_ALL}")
            return False

def main():
    """Main function to handle command line arguments"""
    recon = BigBountyRecon()
    
    parser = argparse.ArgumentParser(description='Python Bug Bounty Recon Tool')
    parser.add_argument('-d', '--domain', help='Target domain to recon')
    parser.add_argument('-c', '--category', help='Category of recon tools to use', default='all')
    parser.add_argument('-l', '--list-categories', action='store_true', help='List all available categories')
    parser.add_argument('-e', '--export', action='store_true', help='Export all tools to a JSON file')
    
    if len(sys.argv) == 1:
        recon.print_banner()
        recon.print_usage()
        sys.exit(0)
    
    args = parser.parse_args()
    
    recon.print_banner()
    
    if args.list_categories:
        recon.list_categories()
        sys.exit(0)
        
    if args.export:
        recon.export_tools()
        sys.exit(0)
    
    if not args.domain:
        print(f"{Fore.RED}[!] Error: Domain is required{Style.RESET_ALL}")
        recon.print_usage()
        sys.exit(1)
    
    # Run the specified category
    recon.run_category(args.domain, args.category)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Exiting...{Style.RESET_ALL}")
        sys.exit(0)
