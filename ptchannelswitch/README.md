# WPAtester

A collection of Python-based WPA testing tools for automating and simplifying common wireless security tasks. Each tool is organized in its own folder. **All scripts must be launched under `root`.**

---

## Prerequisites

Before using any of the tools, ensure you have the following installed on your system:

- **Python 3** (`python3`)
- **pip** (`pip3`)
- **Aircrack-ng suite** (`aircrack-ng`, `airodump-ng`, `aireplay-ng`, etc.)
- **Root privileges** for capturing and injecting packets

Additionally, some tools have their own specific dependencies listed below.

---

## Tools

### WPA3 Personal

#### Downgrade

- **Location**: `ptdowngrade/`
- **Dependencies**:
  - `scapy` (install via `pip3 install scapy`)
  - Aircrack-ng tools (for capturing and cracking handshakes)
- **Description**: Scans for vulnerable networks using WPA3 transition mode and utilizes an Evil Twin attack to downgrade encryption to WPA2.

#### CommitOverflow

- **Location**: `ptcommitoverflow/`
- **Dependencies**:
  - `scapy` (install via `pip3 install scapy`)
  - `random` and `sys` (standard Python libraries)
- **Description**: Conducts an SAE-Commit flood denial-of-service attack against vulnerable Mediatek-based routers by extracting scalars and finite-field elements from a PCAP and repeatedly sending crafted SAE-Commit frames.

#### ChannelSwitch

- **Location**: `ptchannelswitch/`
- **Dependencies**:
  - `scapy` (install via `pip3 install scapy`)
  - `iw` (for setting interface channel)
  - `time` and standard Python libraries
- **Description**: Performs a Channel Switch Announcement (CSA) attack by injecting CSA frames to force a chosen client to switch channels, thereby disconnecting it from the network.

#### DragonDrain

- **Location**: `ptdragondrain/`
- **Dependencies**:
  - External `dragondrain-and-time` utility (must be installed and in your `$PATH`):
    - Repository: https://github.com/sramekm/dragondrain-and-time
  - Loaded `ath_masker` module
    - Repository: https://github.com/vanhoefm/ath_masker
  - Aircrack-ng tools
- **Description**: Launches CPU-clogging on the SAE handshake using the Dragondrain methodologies.

### EAP

#### EAPInspector

- **Location**: `pteapinspector/`
- **Dependencies**:
  - `scapy` (install via `pip3 install scapy`)
  - (Optional) `pyshark` for more advanced packet parsing (`pip3 install pyshark`)
- **Description**: Parses and analyzes EAP frames captured on the network to aid in debugging and security assessment of 802.1X authentications. The frames can be captured live via the script or uploaded from existing capture.

#### EAPEvilTwin

- **Location**: `pteapeviltwin/`
- **Dependencies**:
  - `pexpect` (install via `pip3 install pexpect`)
  - `eaphammer` (install via `pip3 install eaphammer`)
  - Standard Python libraries: `argparse`, `sys`, `re`
- **Description**: Non-interactive wrapper for **eaphammer** that automates an Evil Twin credential-capture attack. Supports GTC and MSCHAPv2 downgrades.

---

## Quickstart

Each tool supports a help menu to list available options. From the project root, run:

```bash
sudo python3 <tool_script> -h
```

Replace `<tool_script>` with the main Python script of the desired tool (e.g., `ptdowngrade/ptdowngrade.py`).

Example:

```bash
sudo python3 ptdowngrade/ptdowngrade.py -h
```

---
