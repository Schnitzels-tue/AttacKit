# AttacKit

**AttacKit** is a command-line tool designed for performing various network attacks including ARP spoofing, DNS spoofing, and SSL stripping via ARP or DNS. It is intended for educational use by penetration testers and network security researchers to simulate and analyze insecure environments.

> ⚠️ **Warning**: This tool is for ethical and legal use only. Unauthorized use on networks without permission is illegal and unethical.

## Features

- ARP Spoofing (targeted or broadcast)
- DNS Spoofing
- SSL Stripping via ARP or DNS
- Quiet Mode for stealthy, precise attacks
- All-Out Mode for broad, aggressive network disruption

## Installation

### Prerequisites

Before running or developing AttacKit, ensure the following dependencies are installed:

**Linux:**

- **Debian/Ubuntu (APT):**
  ```bash
  sudo apt-get install libpcap-dev
  ```

- **Fedora (DNF):**
  ```bash
  sudo dnf install libpcap-devel
  ```

- **Arch Linux (Pacman):**
  ```bash
  sudo pacman -S libpcap
  ```

- **Alpine Linux (APK):**
  ```bash
  sudo apk add libpcap-dev
  ```

**Windows:**

- Install [Npcap](https://nmap.org/npcap/)  
  (choose "Install Npcap in WinPcap API-compatible Mode" if prompted)

**Homebrew:**
- brew install libpcap

## Usage

```bash
attackit [OPTIONS] COMMAND [COMMAND OPTIONS]
```

### Modes of Operation

- `--quiet` – Enables silent, targeted attacks. Requires specific victim IPs and spoof targets.
- `--all-out` – Enables aggressive, broadcast attacks. Targets all devices on the network.

> ⚠️ `--quiet` and `--all-out` are mutually exclusive.

### Commands

#### `--arp`

Performs an ARP spoofing attack.

```bash
attackit --arp ifaceIpOrName [attackerMac] [victimIp] [ipToSpoof]
```

- In **quiet mode**: `victimIp` and `ipToSpoof` are required
- In **all-out mode**: only `ifaceIpOrName` is required
- Multiple IPs can be comma-separated

#### `--dns`

Performs a DNS spoofing attack.

```bash
attackit --dns ifaceIpOrName attackerIp [victimIps] [domainsToSpoof]
```

- In **quiet mode**: both `victimIps` and `domainsToSpoof` must be specified
- Use comma-separated lists for multiple values

#### `--ssldns`

Performs DNS-based SSL stripping.

```bash
attackit --ssldns ifaceIpOrName attackerIp victimIps domainsToStrip
```

- All arguments are required

#### `--sslarp`

Performs ARP-based SSL stripping.

```bash
attackit --sslarp ifaceIpOrName victimIps domainsToStrip
```

- All arguments are required

## Examples

**All-out ARP spoofing:**
```bash
attackit --arp eth0 --all-out
```

**Targeted (quiet) DNS spoofing:**
```bash
attackit --quiet --dns eth0 192.168.1.10 192.168.1.15 example.com,google.com
```

## Exit Codes

- `0` – Success
- `1` – Error or exception occurred

## Developer Notes

To build or modify AttacKit, install the required `libpcap` development package for your system:

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

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author & Support

- Developed by the **AttacKit Team**
- Report bugs or issues at: [GitHub Issues](https://github.com/Schnitzels-tue/AttacKit/issues)
