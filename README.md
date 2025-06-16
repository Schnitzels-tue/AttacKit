# AttacKit

<!--toc:start-->
- [AttacKit](#attackit)
  - [Features](#features)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Modes of Operation](#modes-of-operation)
    - [Modes and Functions](#modes-and-functions)
  - [Examples](#examples)
  - [Exit Codes](#exit-codes)
  - [Developer Notes](#developer-notes)
  - [License](#license)
  - [Author & Support](#author--support)
<!--toc:end-->

**AttacKit** is a command-line utility for executing network attacks such as ARP
spoofing, DNS spoofing, and SSL stripping. It is intended for educational use
by penetration testers and network security professionals to simulate and
analyze insecure environments.

> ⚠️ **Warning**: Use this tool ethically and legally. Unauthorized use on
> networks without permission is illegal and unethical.

## Features

- ARP spoofing (targeted or broadcast)
- DNS spoofing
- SSL stripping via ARP or DNS
- Quiet mode for stealthy, precision attacks
- All-out mode for broad, aggressive disruption

## Installation

### Prerequisites

Ensure the following dependencies are installed before using or developing
AttacKit:

#### Linux

- **Debian/Ubuntu**:

  ```bash
  sudo apt-get install libpcap-dev
  ```

- **Fedora**:

  ```bash
  sudo dnf install libpcap-devel
  ```

- **Arch Linux**:

  ```bash
  sudo pacman -S libpcap
  ```

- **Alpine Linux**:

  ```bash
  sudo apk add libpcap-dev
  ```

#### Windows

- Install [Npcap](https://nmap.org/npcap/)  
  (Enable "Install Npcap in WinPcap API-compatible Mode" if prompted)

#### macOS (Homebrew)

```bash
brew install libpcap
```

## Usage

```bash
attackit [OPTIONS] COMMAND [COMMAND OPTIONS]
```

### Modes of Operation

- `--quiet` – Enables silent, targeted attacks. Requires victim and spoof IPs.
- `--all-out` – Enables aggressive, broadcast-based attacks across the network.

> ⚠️ `--quiet` and `--all-out` cannot be used together.

### Modes and Functions

AttacKit commands operate differently depending on the mode (`--quiet` or
`--all-out`) and attack type.

#### ARP Spoofing

- **Quiet Mode** (`--quiet --arp`):  
  Targets specific victim IP(s) and spoofed IP(s) for precise ARP poisoning.

  ```bash
  attackit --quiet --arp ifaceIpOrName [attackerMac] victimIp ipToSpoof
  ```

- **All-Out Mode** (`--all-out --arp`):  
  Performs a broad ARP spoofing attack across the entire network.

  ```bash
  attackit --arp ifaceIpOrName --all-out
  ```

#### DNS Spoofing

- **Quiet Mode** (`--quiet --dns`):  
  Spoofs DNS queries for specific victims and domains.

  ```bash
  attackit --quiet --dns ifaceIpOrName attackerIp victimIps domainsToSpoof
  ```

- **All-Out Mode** (Not typically supported for DNS spoofing in this tool)

#### SSL Stripping

- **DNS-Based SSL Stripping** (`--ssldns`):  
  Strips SSL via DNS spoofing for specified victims and domains.

  ```bash
  attackit --ssldns ifaceIpOrName attackerIp victimIps domainsToStrip
  ```

- **ARP-Based SSL Stripping** (`--sslarp`):  
  Strips SSL via ARP spoofing for specified victims and domains.

  ```bash
  attackit --sslarp ifaceIpOrName victimIps domainsToStrip
  ```

## Examples

**All-out ARP spoofing:**

```bash
attackit --arp eth0 --all-out
```

**Targeted (quiet mode) DNS spoofing:**

```bash
attackit --quiet --dns eth0 192.168.1.10 192.168.1.15 \
  example.com,google.com
```

## Exit Codes

- `0` – Success
- `1` – An error or exception occurred

## Developer Notes

To build or contribute to AttacKit, ensure `libpcap` development headers are
installed:

**Debian/Ubuntu:**

```bash
sudo apt install libpcap-dev
```

**Fedora:**

```bash
sudo dnf install libpcap-devel
```

**Arch Linux:**

```bash
sudo pacman -S libpcap
```

**Alpine Linux:**

```bash
sudo apk add libpcap-dev
```

**Windows:**

- Install [Npcap](https://nmap.org/npcap/)

## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for full terms.

## Author & Support

- Developed by the **AttacKit Team**
- Submit bugs and feature requests via  
  [GitHub Issues](https://github.com/Schnitzels-tue/AttacKit/issues)
