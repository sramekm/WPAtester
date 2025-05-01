# scan_module.py
import os
import sys
import subprocess
import time
import datetime
from scapy.all import rdpcap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11
from collections import defaultdict
import glob

def check_root():
    # Verify script is running with root privileges
    if os.geteuid() != 0:
        print("[-] This script must be run with root privileges. Use sudo.")
        sys.exit(1)


def check_tools():
    # Verify all required network tools are installed
    tools = [
        'ip',
        'iw',
        'iwconfig',
        'airodump-ng',
        'airmon-ng',
        'hostapd-mana'
    ]

    missing_tools = []
    for tool in tools:
        if not any(
            os.access(os.path.join(path, tool), os.X_OK)
            for path in os.environ['PATH'].split(os.pathsep)
        ):
            missing_tools.append(tool)

    if missing_tools:
        print(f"[-] Missing required tools: {', '.join(missing_tools)}")
        sys.exit(1)
    else:
        print("All required tools are present.")


def check_interface_exists(interface):
    # Verify the specified interface exists
    if subprocess.run(['ip', 'link', 'show', interface], capture_output=True).returncode:
        print(f"[-] Interface {interface} does not exist.")
        sys.exit(1)


def check_managed_mode(interface):
    # Check if interface is in managed mode
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, check=True)
        if 'Mode:Managed' in result.stdout:
            return True
        else:
            print(f"[-] Interface {interface} is not in managed mode. Please configure it in managed mode.")
            return False
    except Exception as e:
        print(f"[-] Error checking interface {interface} : {e}")
        return False


def set_managed_mode(interface):
    # Switch interface to managed mode
    new_interface_name = interface
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        while new_interface_name.endswith('mon'):
            new_interface_name = new_interface_name[:-3]
        subprocess.run(['ip', 'link', 'set', interface, 'name', new_interface_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['iw', 'dev', new_interface_name, 'set', 'type', 'managed'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', new_interface_name, 'up'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"The {new_interface_name} interface is now in Managed mode.")
        return new_interface_name
    except subprocess.CalledProcessError as e:
        print(f"[-] Error configuring {interface} in Managed mode: {e}")
        sys.exit(1)


def run_airodump(interface, folder, capture_time, bssid=None, channel=None):
    # Run airodump-ng to capture wireless traffic
    cmd = ['airodump-ng', interface, '-w', f'{folder}/discovery', '--output-format', 'pcap', '--manufacturer', '--wps', '--band', 'abg']
    if bssid:
        cmd += ['--bssid', bssid]
    if channel:
        cmd += ['-c', str(channel)]
    print(f"Running airodump-ng on {interface} for {capture_time}s...")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(capture_time)
    proc.terminate()
    print(f"Capture done. Files in {folder}/discovery")


def parse_rsn_info(rsn_info):
    # Parse RSN (Robust Security Network) information
    version = "Unknown"
    ciphers = []
    auths = []
    mfp = "Inactive"

    rsn_version = int.from_bytes(rsn_info[0:2], byteorder='little')
    if rsn_version == 1:
        version = "WPA2"
    elif rsn_version == 2:
        version = "WPA3"

    cipher_suite_count = int.from_bytes(rsn_info[6:8], byteorder='little')
    cipher_offset = 8 + cipher_suite_count * 4
    for i in range(cipher_suite_count):
        suite = rsn_info[8 + i*4:12 + i*4]
        if suite[3] == 2:
            ciphers.append("TKIP")
        elif suite[3] == 4:
            ciphers.append("CCMP")
        elif suite[3] == 8:
            ciphers.append("GCMP")

    akm_count = int.from_bytes(
        rsn_info[cipher_offset:cipher_offset+2], byteorder='little'
    )
    akm_offset = cipher_offset + 2
    for i in range(akm_count):
        akm = rsn_info[akm_offset + i*4:akm_offset + (i+1)*4]
        if akm[3] == 1:
            auths.append("802.1X (Enterprise)")
        elif akm[3] == 2:
            auths.append("PSK")
        elif akm[3] == 8:
            auths.append("SAE")
            version = "WPA3"

    rsn_caps = int.from_bytes(
        rsn_info[akm_offset + akm_count*4:
                 akm_offset + akm_count*4 + 2],
        byteorder='little'
    )
    if rsn_caps & 0b01000000:
        mfp = "Optional"
    if rsn_caps & 0b10000000:
        mfp = "Required"

    return version, ", ".join(ciphers), ", ".join(auths), mfp


def get_security_info(packet):
    # Extract WiFi security information from packet
    ssid = packet[Dot11Elt].info.decode(errors="ignore")
    rsn = None
    wpa = None

    elt = packet[Dot11Elt]
    while elt:
        if elt.ID == 48:
            rsn = elt.info
        elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):
            wpa = elt.info
        elt = elt.payload.getlayer(Dot11Elt)

    if rsn:
        version, cipher, auth, mfp = parse_rsn_info(rsn)
    elif wpa:
        version, cipher, auth, mfp = "WPA", "TKIP", "PSK", "Inactive"
    else:
        version, cipher, auth, mfp = "Unknown", "Unknown", "Unknown", "Inactive"

    return ssid, version, cipher, auth, mfp


def extract_channel(packet):
    # Extract WiFi channel from packet
    channel = None
    if packet.haslayer(Dot11Beacon):
        try:
            channel = packet[Dot11Beacon].channel
        except AttributeError:
            pass
    elif packet.haslayer(Dot11ProbeResp):
        try:
            channel = packet[Dot11ProbeResp].channel
        except AttributeError:
            pass

    if channel is None and packet.haslayer(Dot11):
        dot = packet[Dot11]
        channel = getattr(dot, 'channel', None) or getattr(dot, 'Current Channel', None)

    return channel


def analyze_pcap(file):
    # Analyze capture file for vulnerable access points
    packets = rdpcap(file)
    ssid_info = defaultdict(list)
    for p in packets:
        if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
            ssid, version, cipher, auth, mfp = get_security_info(p)
            ch = extract_channel(p)
            ssid_info[ssid].append({
                "Version": version, "Cipher": cipher,
                "Auth": auth, "MFP": mfp,
                "BSSID": p[Dot11].addr3, "Channel": ch
            })
    vulnerable = []
    seen = set()
    for ssid, details in ssid_info.items():
        for d in details:
            if d['BSSID'] not in seen and 'SAE' in d['Auth'] and 'PSK' in d['Auth']:
                seen.add(d['BSSID'])
                vulnerable.append({
                    'SSID': ssid, 'BSSID': d['BSSID'], 'Channel': d['Channel'],
                    'Version': d['Version'], 'Cipher': d['Cipher'],
                    'Auth': d['Auth'], 'MFP': d['MFP']
                })
    if not vulnerable:
        print("No vulnerable APs found.")
    else:
        for ap in vulnerable:
            print(f"\n[VULNERABLE AP]: {ap}")
    return vulnerable


def scan(args):
    # Main scan function
    check_root()
    check_tools()

    if args.iface:
        check_interface_exists(args.iface)
        if args.time is None:
            print("[-] You must specify --time when using --iface for live capture.")
            sys.exit(1)

    if args.file:
        if not os.path.isfile(args.file):
            print(f"[-] The file {args.file} does not exist or is not a valid file.")
            sys.exit(1)

    if not (args.iface or args.file):
        print("[-] Provide --iface or --file.")
        sys.exit(1)

    folder = datetime.datetime.now().strftime("scan-%Y-%m-%d-%H-%M")
    os.makedirs(folder, exist_ok=True)

    if args.iface:
        check_interface_exists(args.iface)
        run_airodump(args.iface, folder, args.time, args.bssid, args.channel)

    # Determine pcap file to analyze
    if args.file:
        pcap_path = args.file
    else:
        # Search for any .pcap or .cap files matching the airodump prefix
        candidates = glob.glob(f"{folder}/discovery-*.pcap") + glob.glob(f"{folder}/discovery-*.cap")
        if not candidates:
            print(f"[-] No capture files found in {folder}")
            sys.exit(1)
        # Use the first match
        pcap_path = candidates[0]

    analyze_pcap(pcap_path)