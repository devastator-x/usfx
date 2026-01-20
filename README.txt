USFX - Ultimate Subdomain Finder X
===================================

A standalone Python CLI tool for discovering subdomains on internal
networks using custom DNS servers. Designed for air-gapped environments
without internet connectivity.


FEATURES
--------

  - Custom DNS Server Support: Specify internal DNS servers
  - Offline-Only Modules: All techniques work without internet
  - 12 Enumeration Modules:
      * DNS Brute Force
      * Zone Transfer (AXFR)
      * DNSSEC Walking (NSEC/NSEC3)
      * DNS Record Mining (MX, NS, TXT, SRV, SOA, CAA)
      * Reverse DNS Sweep
      * CNAME Chain Analysis
      * Subdomain Permutation
      * Recursive Sub-subdomain Enumeration
      * Virtual Host Discovery
      * TLS Certificate SAN Extraction
      * Subdomain Takeover Detection (NEW)
      * Web Technology Detection with Wappalyzer (NEW)
  - Pipeline Modes: Output formats for tool chaining (subs, web, ips, json)
  - Multiple Output Formats: JSON, CSV, TXT
  - Bundled Wordlists: Small (~500), Medium (~3500), Large (~18000)
  - Progress Tracking: Real-time progress with Rich terminal UI


INSTALLATION
------------

From PyPI (Recommended):

    pip install usfx

    # With Wappalyzer support for web technology detection
    pip install usfx[webtech]

From GitHub Releases:

    # Download wheel from:
    # https://github.com/devastator-x/usfx/releases/latest
    pip install usfx-1.2.0-py3-none-any.whl

From Source (Development):

    git clone https://github.com/devastator-x/usfx.git
    cd usfx
    pip install -e .


QUICK START
-----------

Basic Usage:

    usfx corp.local                              # System DNS
    usfx corp.local -d 192.168.1.1               # Internal DNS
    usfx corp.local -d 192.168.1.1 -d 10.0.0.1   # Multiple DNS

Wordlist Options:

    usfx corp.local -d 10.0.0.1 -s small         # ~500 words
    usfx corp.local -d 10.0.0.1 -s medium        # ~3500 words (default)
    usfx corp.local -d 10.0.0.1 -s large         # ~18000 words
    usfx corp.local -d 10.0.0.1 -w /path/to/custom.txt

Output Options:

    usfx corp.local -d 10.0.0.1 -o results.json
    usfx corp.local -d 10.0.0.1 -o results.csv -f csv
    usfx corp.local -d 10.0.0.1 -o results.txt -f txt

Module Selection:

    usfx corp.local -d 10.0.0.1 -m bruteforce,zone,records

    Available modules:
      bruteforce  - DNS brute force with wordlist
      zone        - Zone transfer (AXFR)
      dnssec      - DNSSEC zone walking
      records     - DNS record mining
      reverse     - Reverse DNS sweep
      cname       - CNAME chain analysis
      permutation - Subdomain permutation
      recursive   - Recursive sub-subdomain enumeration
      vhost       - Virtual host discovery
      tls         - TLS certificate analysis
      takeover    - Subdomain takeover detection
      webtech     - Web technology detection

Extended Scanning (NEW):

    # Subdomain takeover vulnerability detection
    usfx corp.local -d 10.0.0.1 --takeover

    # Web technology detection (requires python-Wappalyzer)
    usfx corp.local -d 10.0.0.1 --web-tech

    # Custom web ports for tech detection
    usfx corp.local -d 10.0.0.1 --web-tech --web-ports 80,443,8080,8443

Pipeline Modes (NEW):

    # Output only subdomains (one per line) - pipe to other tools
    usfx corp.local -d 10.0.0.1 --pipe-subs | httpx

    # Output only web URLs
    usfx corp.local -d 10.0.0.1 --web-tech --pipe-web

    # Output only IP addresses
    usfx corp.local -d 10.0.0.1 --pipe-ips | nmap -iL -

    # JSON output to stdout (for jq processing)
    usfx corp.local -d 10.0.0.1 --pipe-json | jq '.subdomains'

Advanced Options:

    usfx corp.local -d 10.0.0.1 -t 50 --timeout 5.0
    usfx corp.local -d 10.0.0.1 --reverse-range 192.168.0.0/24
    usfx corp.local -d 10.0.0.1 --vhost-ip 192.168.1.100
    usfx corp.local -d 10.0.0.1 -v    # Verbose
    usfx corp.local -d 10.0.0.1 -q    # Quiet


CLI REFERENCE
-------------

Usage: usfx [OPTIONS] DOMAIN

Options:
  -d, --dns-server TEXT       DNS server IP (can be repeated)
  -w, --wordlist PATH         Custom wordlist file
  -s, --wordlist-size TEXT    Wordlist size: small|medium|large
  -o, --output PATH           Output file path
  -f, --format TEXT           Output format: json|csv|txt
  -t, --threads INTEGER       Parallel threads (default: 30, max: 100)
  --timeout FLOAT             DNS timeout in seconds (default: 3.0)
  -m, --modules TEXT          Comma-separated module list
  --reverse-range TEXT        CIDR range for reverse DNS
  --vhost-ip TEXT             IP for vhost scanning
  --takeover                  Enable subdomain takeover detection
  --web-tech                  Enable web technology detection
  --web-ports TEXT            Ports for web tech scanning (default: 80,443,8080,8443)
  --pipe-subs                 Pipeline: output subdomains only
  --pipe-web                  Pipeline: output web URLs only
  --pipe-ips                  Pipeline: output IPs only
  --pipe-json                 Pipeline: JSON to stdout
  -v, --verbose               Verbose output
  -q, --quiet                 Suppress non-essential output
  --no-color                  Disable colored output
  --version                   Show version
  --help                      Show help message


PYTHON API
----------

    from usfx import ScanConfig, SubdomainEngine
    from usfx.config import WordlistSize

    config = ScanConfig(
        domain='corp.internal',
        dns_servers=['10.0.0.1', '10.0.0.2'],
        wordlist_size=WordlistSize.MEDIUM,
        threads=50,
        timeout=3.0,
        takeover=True,      # Enable takeover detection
        web_tech=True,      # Enable web tech detection
    )

    engine = SubdomainEngine()
    result = engine.scan(config)

    print(f"Found {result.total_found} subdomains")
    for sub in result.subdomains:
        print(f"  {sub.subdomain} -> {sub.ip}")

    # Takeover vulnerabilities
    for vuln in result.takeover_results:
        print(f"  VULN: {vuln.subdomain} -> {vuln.service}")

    # Web technologies
    for web in result.web_tech_results:
        print(f"  WEB: {web.url} - {', '.join(web.technologies)}")


MODULE DESCRIPTIONS
-------------------

  dns_bruteforce   Wordlist-based DNS queries           Medium
  zone_transfer    AXFR zone transfer attempts          Fast
  dnssec_walker    NSEC/NSEC3 zone walking              Fast
  dns_records      MX/NS/TXT/SRV/SOA/CAA mining         Fast
  reverse_dns      PTR lookups on IP ranges             Slow
  cname_chaser     CNAME chain tracking                 Fast
  permutation      Subdomain variation generation       Medium
  recursive_enum   Sub-subdomain discovery              Medium
  vhost_scanner    Host header brute force              Slow
  tls_analyzer     TLS certificate SAN extraction       Medium
  takeover         Subdomain takeover detection         Fast
  web_tech         Web technology detection             Medium


REQUIREMENTS
------------

  - Python 3.10+
  - dnspython >= 2.4.0
  - click >= 8.1.0
  - requests >= 2.28.0
  - cryptography >= 41.0.0
  - rich >= 13.0.0

Optional:
  - python-Wappalyzer >= 0.3.1 (for web technology detection)


USE CASES
---------

Internal Network Penetration Testing:
    usfx corp.internal -d 10.0.0.53 -s large --takeover -o findings.json

Active Directory Reconnaissance:
    usfx ad.corp.local -d 192.168.1.1 -m records,reverse,zone

IT Asset Discovery:
    usfx internal.company -d 172.16.0.1 --reverse-range 172.16.0.0/16

Web Application Mapping:
    usfx corp.local -d 10.0.0.1 --web-tech --pipe-web | httpx -silent

Tool Integration:
    usfx corp.local --pipe-subs | nuclei -t takeovers/


LICENSE
-------

MIT License - See LICENSE file for details.
