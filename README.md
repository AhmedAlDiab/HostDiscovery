# HostDiscovery

**HostDiscovery** is a Python automation tool designed to optimize network host discovery. It utilizes a two-stage scanning process to ensure maximum detection accuracy, filtering out false negatives by retrying hosts that block standard ICMP requests using customizable TCP and UDP probes.

---

## ✨ Features

- **Dual-Stage Detection Logic**:
  - **Stage 1**: Performs a fast ICMP/ARP discovery scan (`-sn`).
  - **Stage 2**: Automatically targets hosts marked as "down" in Stage 1 and retries them using TCP (`-PS`) and UDP (`-PU`) ping probes.
- **Interactive Progress Monitoring**: While Nmap is running, you can press **Enter** or **Spacebar** at any time to display the live percentage completion and elapsed time natively.
- **Flexible Port Customization**:
  - Support for standard flags: `--tcp 22,80,443`
  - Support for compact syntax: `-tcp22,80,443` or `-tcp1-1000`
- **Clean Output Management**: Automatically sorts and saves results into two separate text files for easy integration with other security tools.
- **Professional Terminal UI**: Uses color-coded status messages (Gold for Info, Green for Success, Red for Errors) for high readability.

---

## 🛠 Requirements

- **Python 3.6+**
- **Nmap**: Must be installed and available in your system's PATH.

### Installation of Nmap
- **Linux (Ubuntu/Debian)**: `sudo apt install nmap`
- **macOS**: `brew install nmap`
- **Windows**: Download from [nmap.org](https://nmap.org/download.html) and ensure "Add to PATH" is checked during installation.

---

## 🚀 Usage

### Syntax
```bash
python3 HostDiscovery.py [OPTIONS] <target>
```

### Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| `target` | IP, CIDR block, range, or domain. | **Required** |
| `--tcp PORTS` | TCP ports for the Stage 2 `-PS` probe. | `22,80,135,139,443,445,3389` |
| `-tcp<PORTS>` | Compact syntax for TCP ports (e.g., `-tcp80,443`). | (Same as above) |
| `--udp PORTS` | UDP ports for the Stage 2 `-PU` probe. | `53,67,68,69,123,137,138,161,500,1900` |
| `-udp<PORTS>` | Compact syntax for UDP ports (e.g., `-udp1-500`). | (Same as above) |
| `-h`, `--help` | Displays the help menu and usage examples. | N/A |

---

## 📝 Examples

**1. Standard Subnet Scan**
```bash
python3 HostDiscovery.py 192.168.1.0/24
```

**2. Targeted Port Probe (Bypassing specific firewalls)**
```bash
python3 HostDiscovery.py 10.0.0.0/24 -tcp22,80,443 -udp53
```

**3. Large Range Scan**
```bash
python3 HostDiscovery.py 172.16.0.0/16 -tcp1-1000 -udp1-500
```

**4. Multiple Targets**
```bash
python3 HostDiscovery.py 192.168.1.10 192.168.1.50 scanme.nmap.org
```

---

## ⏳ Interactive Progress

One of the key features of this tool is the ability to check progress without interrupting the scan. When the script indicates it is running a stage:

1. Press the **Enter** or **Spacebar** key.
2. Nmap will immediately print the current scan status (e.g., `Stats: 0:00:05 elapsed; 0 hosts completed (100% done)`).

---

## 📂 Output Files

Upon completion, the script generates the following files in the execution directory:

- **`live_hosts.txt`**: A sorted list of all hosts detected as "Up" across both stages.
- **`down_hosts.txt`**: A sorted list of hosts that remained undetectable after both stages.

---

## 📜 Copyright

© AhmedAlDiab

---

**Disclaimer**: *This tool is intended for authorized security testing, auditing, and educational purposes only. Ensure you have explicit written permission before scanning any network or host you do not own.*