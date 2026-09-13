# roromero-scanner

A simple, fast, multi-threaded TCP port scanner written in Python. Built as a learning project to practice sockets, concurrency, and CLI tooling.

## Features

- Multi-threaded TCP connect scan (no root/admin privileges required)
- Custom port ranges: single ports, lists, ranges, or a mix (`22,80,1000-1010`)
- Optional banner grabbing on open ports
- Adjustable timeout and thread count
- Clean, readable output

## Requirements

- Python 3.8+
- No external dependencies (standard library only)

## Usage

```bash
python3 portscanner.py <target> [options]
```

| Option | Description | Default |
|---|---|---|
| `target` | IP address or hostname to scan | required |
| `-p, --ports` | Ports to scan, e.g. `80`, `1-1000`, `22,80,443` | common ports list |
| `-t, --threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout in seconds | `1.0` |
| `-b, --banner` | Attempt to grab service banners on open ports | off |
| `-v, --verbose` | Also show closed/filtered ports | off |

## Examples

```bash
# Scan common ports
python3 portscanner.py 192.168.1.1

# Scan a specific range with banner grabbing
python3 portscanner.py scanme.nmap.org -p 1-1000 -b

# Scan specific ports, verbose output
python3 portscanner.py 10.0.0.5 -p 22,80,443,3389 -v
```

## ⚠️ Responsible use

Only scan systems you own or have explicit permission to test (your own machines, authorized lab environments like HTB/TryHackMe, or written authorization). Scanning systems without permission may be illegal in your jurisdiction.

## License

MIT
