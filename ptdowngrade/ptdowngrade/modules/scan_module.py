# scan_module.py
import os
import sys
import subprocess
import time
import datetime
import glob
from collections import defaultdict
from scapy.all import rdpcap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11
from scapy.error import Scapy_Exception

from ptlibs import ptjsonlib, ptprinthelper
from ptlibs.ptprinthelper import ptprint

ptjsonlib_object = None
args_global = None

def check_root():
    # Verify that the script is running with root privileges
    if os.geteuid() != 0:
        ptjsonlib_object.end_error("This script must be run with root privileges. Use sudo.", args_global.json)

def check_tools():
    # Verify that all required tools are installed on the system
    tools = [
        'ip', 'iw', 'iwconfig', 'airodump-ng', 'airmon-ng', 'hostapd-mana'
    ]

    # Check each tool by looking for executable in PATH
    missing_tools = [
        tool for tool in tools
        if not any(os.access(os.path.join(path, tool), os.X_OK)
                  for path in os.environ['PATH'].split(os.pathsep))
    ]

    if missing_tools:
        ptjsonlib_object.end_error(f"Missing required tools: {', '.join(missing_tools)}", args_global.json)
    else:
        ptprint("All required tools are present.", bullet_type="INFO", condition=not args_global.json)

def check_interface_exists(interface):
    # Validate that the specified wireless interface exists in the system
    cmd = ['ip', 'link', 'show', interface]
    if subprocess.run(cmd, capture_output=True).returncode:
        msg = f"Interface {interface} does not exist."
        if ptjsonlib_object:
            ptjsonlib_object.end_error(msg, args_global.json)
        else:
            print(f"[-] {msg}")
            sys.exit(1)

def check_managed_mode(interface):
    # Check if the wireless interface is in managed mode
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, check=True)
        if 'Mode:Managed' in result.stdout:
            return True
        else:
            ptprint(f"Interface {interface} is not in managed mode. Please configure it in managed mode.", 
                   bullet_type="ERROR", condition=not args_global.json)
            return False
    except Exception as e:
        ptprint(f"Error checking interface {interface} : {e}", bullet_type="ERROR", condition=not args_global.json)
        return False

def set_managed_mode(interface):
    # Configure the wireless interface to use managed mode
    new_interface_name = interface
    try:
        # Take interface down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Remove 'mon' suffix if it exists (monitors typically have 'mon' appended)
        while new_interface_name.endswith('mon'):
            new_interface_name = new_interface_name[:-3]
            
        subprocess.run(['ip', 'link', 'set', interface, 'name', new_interface_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        subprocess.run(['iw', 'dev', new_interface_name, 'set', 'type', 'managed'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        subprocess.run(['ip', 'link', 'set', new_interface_name, 'up'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        ptprint(f"The {new_interface_name} interface is now in Managed mode.", bullet_type="INFO", condition=not args_global.json)

        return new_interface_name
    except subprocess.CalledProcessError as e:
        ptjsonlib_object.end_error(f"Error configuring {interface} in Managed mode: {e}", args_global.json)

def run_airodump(interface, folder, capture_time, bssid=None, channel=None):
    # Run airodump-ng to capture wireless packets for analysis
    cmd = ['airodump-ng', interface, '-w', f'{folder}/discovery', '--output-format', 'pcap', 
           '--manufacturer', '--wps', '--band', 'abg']
    
    # Filter by BSSID if provided
    if bssid:
        cmd += ['--bssid', bssid]
        
    # Filter by channel if provided
    if channel:
        cmd += ['-c', str(channel)]
        
    ptprint(f"Running airodump-ng on {interface} for {capture_time}s...", bullet_type="INFO", condition=not args_global.json)

    try:
        # Start capture in background process
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(capture_time)
        proc.terminate()
        ptprint(f"Capture done. Files in {folder}/discovery", bullet_type="INFO", condition=not args_global.json)
    except KeyboardInterrupt:
        proc.terminate()
        if args_global.json:
            ptjsonlib_object.end_error("Capture aborted by user", args_global.json)
        else:
            ptprint("Capture aborted by user", bullet_type="ERROR", condition=not args_global.json)
        sys.exit(1)
    except Exception as e:
        ptjsonlib_object.end_error(f"Error running airodump-ng: {e}", args_global.json)


def parse_rsn_info(rsn_info):
    # Parse Robust Security Network (RSN) information from beacon frames
    version = "Unknown"
    ciphers = []
    auths = []
    mfp = "Inactive"

    # Extract version from first 2 bytes
    rsn_version = int.from_bytes(rsn_info[0:2], byteorder='little')
    if rsn_version == 1:
        version = "WPA2"
    elif rsn_version == 2:
        version = "WPA3"
    
    # Parse pairwise cipher suites - bytes 6-7 contain the count
    cipher_suite_count = int.from_bytes(rsn_info[6:8], byteorder='little')
    cipher_offset = 8 + cipher_suite_count * 4
    
    # Extract each cipher suite (4 bytes each)
    for i in range(cipher_suite_count):
        suite = rsn_info[8 + i*4:12 + i*4]
        if suite[3] == 2:
            ciphers.append("TKIP")
        elif suite[3] == 4:
            ciphers.append("CCMP")
        elif suite[3] == 8:
            ciphers.append("GCMP")

    # Parse authentication key management (AKM) suites
    akm_count = int.from_bytes(rsn_info[cipher_offset:cipher_offset+2], byteorder='little')
    akm_offset = cipher_offset + 2
    
    # Extract each AKM suite (4 bytes each)
    for i in range(akm_count):
        akm = rsn_info[akm_offset + i*4:akm_offset + (i+1)*4]
        # Check the last byte for auth type
        if akm[3] == 1:
            auths.append("802.1X (Enterprise)")
        elif akm[3] == 2:
            auths.append("PSK")
        elif akm[3] == 8:
            auths.append("SAE")  # SAE is used in WPA3
            version = "WPA3"

    # Parse RSN capabilities for management frame protection (MFP)
    rsn_caps = int.from_bytes(rsn_info[akm_offset + akm_count*4:akm_offset + akm_count*4 + 2], byteorder='little')
    if rsn_caps & 0b01000000:  # Bit 6 for optional MFP
        mfp = "Optional"
    if rsn_caps & 0b10000000:  # Bit 7 for required MFP
        mfp = "Required"

    return version, ", ".join(ciphers), ", ".join(auths), mfp


def get_security_info(packet):
    # Extract security information from a Wi-Fi packet
    ssid = packet[Dot11Elt].info.decode(errors="ignore")
    rsn = None
    wpa = None

    # Navigate through the information elements to find security info
    elt = packet[Dot11Elt]
    while elt:
        if elt.ID == 48:  # RSN information element ID
            rsn = elt.info
        elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):  # WPA vendor specific
            wpa = elt.info
        elt = elt.payload.getlayer(Dot11Elt)

    # Parse the security information
    if rsn:
        version, cipher, auth, mfp = parse_rsn_info(rsn)
    elif wpa:
        version, cipher, auth, mfp = "WPA", "TKIP", "PSK", "Inactive"
    else:
        version, cipher, auth, mfp = "Unknown", "Unknown", "Unknown", "Inactive"

    return ssid, version, cipher, auth, mfp


def extract_channel(packet):
    # Extract the channel information from a Wi-Fi packet
    channel = None
    
    # Try to get channel from beacon frames
    if packet.haslayer(Dot11Beacon):
        try:
            channel = packet[Dot11Beacon].channel
        except AttributeError:
            pass
    # Try to get channel from probe response frames
    elif packet.haslayer(Dot11ProbeResp):
        try:
            channel = packet[Dot11ProbeResp].channel
        except AttributeError:
            pass

    # If still not found, try to get from Dot11 layer
    if channel is None and packet.haslayer(Dot11):
        dot = packet[Dot11]
        channel = getattr(dot, 'channel', None) or getattr(dot, 'Current Channel', None)

    return channel


def analyze_pcap(file_path):
    # Analyze a pcap file to find AP vulnerabilities
    try:
        packets = rdpcap(file_path)
    except (Scapy_Exception, FileNotFoundError) as e:
        ptjsonlib_object.end_error(
            f"No packets could be read from captured file: {file_path} ({e})",
            args_global.json
        )
    except Exception as e:
        ptjsonlib_object.end_error(
            f"Error reading pcap file {file_path}: {e}",
            args_global.json
        )

    ssid_info = defaultdict(list)
    try:
        # Process each packet, extracting security information
        for p in packets:
            if not p.haslayer(Dot11Elt):
                continue
            if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
                ssid, version, cipher, auth, mfp = get_security_info(p)
                ch = extract_channel(p)
                ssid_info[ssid].append({
                    "Version": version, "Cipher": cipher,
                    "Auth": auth, "MFP": mfp,
                    "BSSID": p[Dot11].addr3, "Channel": ch
                })
    except IndexError as e:
        ptjsonlib_object.end_error(
            f"Malformed RSN info in packet: {e}",
            args_global.json
        )

    # Identify vulnerable APs (supporting both SAE and PSK auth)
    vulnerable = []
    seen = set()
    for ssid, details in ssid_info.items():
        for d in details:
            # Check if this AP supports both SAE and PSK authentication methods
            if d['BSSID'] not in seen and 'SAE' in d['Auth'] and 'PSK' in d['Auth']:
                seen.add(d['BSSID'])
                vulnerable.append({
                    'SSID': ssid, 'BSSID': d['BSSID'], 'Channel': d['Channel'],
                    'Version': d['Version'], 'Cipher': d['Cipher'],
                    'Auth': d['Auth'], 'MFP': d['MFP']
                })

    # Report results
    if not vulnerable:
        ptprint("No vulnerable APs found.", bullet_type="INFO", condition=not args_global.json)
    else:
        for ap in vulnerable:
            ptprint("\n[AP VULNERABLE TO DOWNGRADE] :", bullet_type="TEXT", condition=not args_global.json)
            ptprint(f"  - SSID: {ap['SSID']}", bullet_type="TEXT", condition=not args_global.json)
            ptprint(f"  - BSSID: {ap['BSSID']}", bullet_type="TEXT", condition=not args_global.json)
            ptprint(f"  - Channel: {ap['Channel']}", bullet_type="TEXT", condition=not args_global.json)
            ptprint(f"  - Security Protocol: {ap['Version']}", bullet_type="TEXT", condition=not args_global.json)
            ptprint(f"  - Cipher: {ap['Cipher']}", bullet_type="TEXT", condition=not args_global.json)
            ptprint(f"  - Authentication: {ap['Auth']}", bullet_type="TEXT", condition=not args_global.json)
            ptprint(f"  - MFP: {ap['MFP']}", bullet_type="TEXT", condition=not args_global.json)

    return vulnerable

def scan(args):
    # Main function that orchestrates the scanning process
    global args_global, ptjsonlib_object
    
    ptjsonlib_object = ptjsonlib.PtJsonLib()
    args_global = args

    try:
        # Perform initial checks
        check_root()
        check_tools()

        # Validate input arguments
        if args.iface:
            check_interface_exists(args.iface)
            if args.time is None:
                ptjsonlib_object.end_error("You must specify --time when using --iface for live capture.", args_global.json)

        if args.file:
            if not os.path.isfile(args.file):
                ptjsonlib_object.end_error(f"The file {args.file} does not exist or is not a valid file.", args_global.json)

        if not (args.iface or args.file):
            ptjsonlib_object.end_error("Provide --iface or --file.", args_global.json)

        # Create output folder with timestamp
        folder = datetime.datetime.now().strftime("scan-%Y-%m-%d-%H-%M")
        os.makedirs(folder, exist_ok=True)

        # Run capture if interface is provided
        if args.iface:
            run_airodump(args.iface, folder, args.time, args.bssid, args.channel)

        # Determine which pcap file to analyze
        if args.file:
            pcap_path = args.file
        else:
            candidates = glob.glob(f"{folder}/discovery-*.pcap") + glob.glob(f"{folder}/discovery-*.cap")
            if not candidates:
                ptjsonlib_object.end_error(f"No capture files found in {folder}", args_global.json)
            pcap_path = candidates[0]

        # Analyze the pcap file
        vulnerable = analyze_pcap(pcap_path)

        # Generate JSON output for vulnerable APs if requested
        if args_global.json and vulnerable:
            for ap in vulnerable:
                ptjsonlib_object.add_vulnerability(
                    "PTV-WPA-TRANSITION",
                    vuln_request=(
                        f"AP with SSID: {ap['SSID']}, BSSID: {ap['BSSID']} on channel {ap['Channel']} supports both SAE and PSK (WPA3-Transition mode)"
                    ),
                    vuln_response=(
                        f"Found vulnerable AP '{ap['SSID']}' ({ap['BSSID']}); potential downgrade attack target."
                    )
                )

        ptjsonlib_object.set_status("finished")
        ptprint(ptjsonlib_object.get_result_json(), "", args_global.json)

    except KeyboardInterrupt:
        if args_global.json:
            ptjsonlib_object.end_error("Scan aborted by user", args_global.json)
        else:
            ptprint("Scan aborted by user", bullet_type="ERROR", condition=not args_global.json)
        sys.exit(1)
