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

Building attackit requires the following dependencies:
- Libpcap/Npcap
-  LibSSL
-  boost
AttacKit:

#### Linux

- **Debian/Ubuntu**:

  ```bash

  sudo apt-get install libpcap-dev
  sudo apt-get install libssl-dev
  sudo apt-get install libboost-all-dev
  ```

- **Fedora**:

  ```bash
  sudo dnf install libpcap-devel
  sudo dnf install openssl-devel
  sudo dnf install boost-devel
  ```

- **Arch Linux**:

  ```bash
  sudo pacman -S libpcap
  sudo pacman -S openssl
  sudo pacman -S boost
  ```

- **Alpine Linux**:

  ```bash
  sudo apk add libpcap-dev
  sudo apk add openssl-dev
  sudo apk add boost-dev
  ```

#### Windows

- Install [Npcap](https://nmap.org/npcap/)
  (Enable "Install Npcap in WinPcap API-compatible Mode" if prompted)
- Download the [npcap-sdk](https://npcap.com/#download), rename it to ``npcap-sdk`` and put it into the thirdparty folder
- Install [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)
- Download the [boost-sdk](https://www.boost.org/releases/latest/), rename it to ``boost-sdk`` and put it into the thirdpary folder

#### macOS (Homebrew) Currently doesn't work

```bash
brew install libpcap
brew install openssl
brew install boost
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

## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for full terms.

## Author & Support

- Developed by the **AttacKit Team**
- Submit bugs and feature requests via  
  [GitHub Issues](https://github.com/Schnitzels-tue/AttacKit/issues)
