# BigBountyRecon-P
# BigBountyRecon - Python Version
# version 1 (beta) by merlin777 and claude.ai

A Python implementation similar to the original [BigBountyRecon](https://github.com/Viralmaniar/BigBountyRecon), automating reconnaissance processes during bug bounty hunting by integrating various online tools in one place.

## Features

- Automated recon with 20+ tool categories
- Simple and intuitive command-line interface
- Color-coded output for better visibility
- Easily extendable for adding new tools
- Option to export tool list to JSON

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/BigBountyRecon-Python.git
cd BigBountyRecon-Python

# Install required packages
pip install -r requirements.txt
```

## Usage

```bash
# List all available categories
python BigBountyRecon.py --list-categories

# Run specific category recon for a domain
python BigBountyRecon.py -d example.com -c subdomain-enum

# Run all recon tools for a domain
python BigBountyRecon.py --domain example.com --category all

# Export tools to JSON
python BigBountyRecon.py --export
```

## Available Categories

- `all`: Run all the tools
- `subdomain-enum`: Tools for subdomain enumeration
- `subdomain-takeover`: Tools for subdomain takeover
- `port-scanning`: Tools for port scanning
- `screenshots`: Tools for website screenshots
- `url-extraction`: URL extraction tools
- `js-hunting`: Tools for JavaScript hunting
- `content-discovery`: Content discovery tools
- `parameter-discovery`: Parameter discovery tools
- `ip-info`: IP information tools
- `cors-misconfiguration`: CORS misconfiguration tools
- `s3-buckets`: S3 bucket tools
- `dns-info`: DNS information tools
- `directory-fuzzing`: Directory fuzzing tools
- `visual-recon`: Visual recon tools
- `tech-stack`: Tech stack detection tools
- `file-analysis`: File analysis tools
- `github-dorks`: GitHub dorks tools
- `wayback-machine`: Wayback machine tools
- `nuclei-templates`: Nuclei templates tools
- `fuzzing`: Fuzzing tools
- `cms-scanners`: CMS scanner tools
- `wordlists`: Wordlist resources
- `other-tools`: Other useful tools

## Screenshots

[Add screenshots here once you've tested the tool]

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/yourusername/BigBountyRecon-Python/issues).

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- Original [BigBountyRecon](https://github.com/Viralmaniar/BigBountyRecon) by Viral Maniar
- All the amazing open-source tools included in this project
