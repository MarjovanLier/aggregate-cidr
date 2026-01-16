# aggregate-cidr

A fast CIDR aggregation tool written in Go. Combines overlapping and adjacent IP address blocks into the smallest possible set of CIDR prefixes.

## Features

- Aggregates adjacent CIDR blocks (e.g., `192.168.1.0/32` + `192.168.1.1/32` → `192.168.1.0/31`)
- Removes overlapping/redundant ranges (e.g., `10.0.0.0/8` contains `10.1.0.0/16`)
- Supports both IPv4 and IPv6
- Handles various input formats:
  - Plain IPs (`192.168.1.1`)
  - CIDR notation (`192.168.1.0/24`)
  - Spamhaus format (`1.2.3.0/24 ; SBL123456`)
  - Comments (`#` or `;` prefixed lines)
- Single static binary with no dependencies

## Installation

```bash
go build -o aggregate-cidr .
```

## Usage

```bash
# From file
aggregate-cidr < ip-list.txt > aggregated.txt

# From pipe
cat blocklist.txt | aggregate-cidr

# Example
echo -e "192.168.1.0/32\n192.168.1.1/32\n192.168.1.2/32\n192.168.1.3/32" | aggregate-cidr
# Output: 192.168.1.0/30
```

## Use Cases

- Optimizing firewall blocklists (ipset, iptables, pf)
- Reducing ipset/nftables set sizes
- Cleaning up threat intelligence feeds
- Consolidating IP allowlists/denylists

## Example: Threat Intelligence Integration

```bash
#!/bin/bash
# Download and aggregate Spamhaus DROP list
curl -s https://www.spamhaus.org/drop/drop.txt | aggregate-cidr > drop-aggregated.txt

# Load into ipset
ipset flush blocklist
while read cidr; do
    ipset add blocklist "$cidr"
done < drop-aggregated.txt
```

## Performance

Processes ~10,000 CIDRs in under 1 second.

## License

MIT License - See LICENSE file.

## Credits

Inspired by the Perl script `aggregate-cidr-addresses` by Mark Suter.
