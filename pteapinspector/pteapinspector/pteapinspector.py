#!/usr/bin/env python3
import argparse
import subprocess
import struct
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
from collections import defaultdict

from scapy.all import (
    sniff,
    rdpcap,
    Dot11,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11Elt,
    EAPOL,
    EAP,
)

from ptlibs import ptjsonlib, ptprinthelper
from ptlibs.ptprinthelper import ptprint

from _version import __version__

ptjsonlib_object = ptjsonlib.PtJsonLib()

# --- Constants & Mappings ---------------------------------------------
CIPHER_MAP = {
    2:  'TKIP',
    4:  'CCMP-128',
    9:  'GCMP-256',
    10: 'CCMP-256',
}

EAP_TYPE_MAP = {
    1:  'Identity',
    2:  'Notification',
    3:  'Nak',
    4:  'MD5-Challenge',
    5:  'One-Time Password',
    6:  'Generic Token Card',
    13: 'TLS',
    21: 'TLS',
    25: 'TTLS',
    26: 'PEAP',
    40: 'PWD',      # RFC-5931
    52: 'PWD',      # as Wireshark shows
    43: 'FAST',
}

networks = defaultdict(lambda: {
    'group':       None,
    'pairwise':    set(),
    'akms':        set(),
    'caps':        None,
    'eap_types':   set(),
    'seen_eapol':  False,
})


def tune_interface(iface, channel):
    # Set the wireless interface to the specified channel
    if iface and channel:
        subprocess.run(
            ['iwconfig', iface, 'channel', str(channel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def capture_packets(args):
    # Capture packets either from a PCAP file or live interface
    try:
        if args.file:
            for pkt in rdpcap(args.file):
                process_packet(pkt)
        else:
            sniff(iface=args.iface, timeout=args.time,
                  prn=process_packet, store=0)
    except KeyboardInterrupt:
        ptjsonlib_object.end_error("Execution interrupted by user", args.json)
    except Exception as e:
        error_msg = str(e)
        if args.json:
            ptjsonlib_object.end_error(error_msg, args.json)
        else:
            ptprint(f"Capture/parse error: {error_msg}", bullet_type="ERROR", condition=not args.json)


def add_mfp_vuln(networks_dict, json_mode):
    # Add vulnerability if EAP networks don't require Management Frame Protection
    no_mfp = [
        f"{ssid} ({bssid})"
        for (ssid, bssid), info in networks_dict.items()
        if info['eap_types'] and not mfp_required(info['caps'])
    ]
    if no_mfp:
        ptjsonlib_object.add_vulnerability(
            "PTV-EAP-NOMFP",
            vuln_request=(
                "MFP is not required, deauthentication of client device is possible"
            ),
            vuln_response=(
                f"Management frame protection is not required for the following networks: "
                f"{', '.join(no_mfp)}"
            )
        )


def add_legacy_eap_vulns(networks_dict):
    # Identify networks using insecure legacy EAP types (GTC and MD5)
    gtc_nets = []
    md5_nets = []
    for (ssid, bssid), info in networks_dict.items():
        if not info['eap_types']:
            continue
        if 6 in info['eap_types']:  # GTC
            gtc_nets.append(f"{ssid} ({bssid})")
        if 4 in info['eap_types']:  # MD5
            md5_nets.append(f"{ssid} ({bssid})")

    if gtc_nets:
        ptjsonlib_object.add_vulnerability(
            "PTV-EAP-GTC",
            vuln_request="GTC legacy authentication used",
            vuln_response=(
                f"Networks using GTC authentication: {', '.join(gtc_nets)}"
            )
        )

    if md5_nets:
        ptjsonlib_object.add_vulnerability(
            "PTV-EAP-MD5",
            vuln_request="MD5-Challenge legacy authentication used",
            vuln_response=(
                f"Networks using MD5-Challenge authentication: {', '.join(md5_nets)}"
            )
        )

def print_summary(networks_dict, args):
    """
    Print human-readable network summary to console.
    Returns True if any network was printed, False otherwise.
    """
    found_any = False
    for (ssid, bssid), info in networks_dict.items():
        if args.bssid and bssid.lower() != args.bssid.lower():
            continue
        if not info['eap_types']:
            continue

        found_any = True
        ptprint('=' * 60, bullet_type="TEXT", condition=not args.json)
        ptprint(f'SSID:   {ssid}',  bullet_type="TEXT", condition=not args.json)
        ptprint(f'BSSID:  {bssid}', bullet_type="TEXT", condition=not args.json)
        ent = detect_enterprise(info['akms'])
        ptprint(f'Protocol version:        {ent}',
                bullet_type="TEXT", condition=not args.json)
        ptprint(f'MFP Required:      {"Yes" if mfp_required(info["caps"]) else "No"}',
                bullet_type="TEXT", condition=not args.json)

        grp_name = CIPHER_MAP.get(info['group'], f'Unknown({info["group"]})')
        pw_names = [CIPHER_MAP.get(p, f'Unknown({p})') for p in sorted(info['pairwise'])]
        ptprint(f'Group cipher:     {grp_name}',
                bullet_type="INFO", condition=not args.json)
        ptprint(f'Pairwise ciphers: {", ".join(pw_names) or "None"}',
                bullet_type="INFO", condition=not args.json)

        entries = [f"{code} ({EAP_TYPE_MAP.get(code, 'Unknown')})"
                   for code in sorted(info['eap_types'])]
        ptprint(f'EAP types seen:   {", ".join(entries)}',
                bullet_type="INFO", condition=not args.json)

    return found_any

def parse_rsn_info(info_bytes):
    # Parse Robust Security Network Information Element according to IEEE-802.11 standard
    pos = 0
    pos += 2  # Skip version field (2 bytes)
    pos += 3  # Skip OUI + type (3 bytes)
    group_cipher = info_bytes[pos]
    pos += 1

    # Parse pairwise ciphers
    pairwise_count = struct.unpack_from('<H', info_bytes, pos)[0]
    pos += 2
    pairwise = []
    for _ in range(pairwise_count):
        pos += 3  # Skip OUI
        pairwise.append(info_bytes[pos])
        pos += 1

    # Parse authentication key management (AKM) types
    akm_count = struct.unpack_from('<H', info_bytes, pos)[0]
    pos += 2
    akms = []
    for _ in range(akm_count):
        pos += 3  # Skip OUI
        akms.append(info_bytes[pos])
        pos += 1

    # Parse RSN capabilities if present
    caps = None
    if pos + 2 <= len(info_bytes):
        caps = struct.unpack_from('<H', info_bytes, pos)[0]

    return {
        'group_cipher':     group_cipher,
        'pairwise_ciphers': pairwise,
        'akm_types':        akms,
        'capabilities':     caps,
    }


def detect_enterprise(akm_list):
    # Determine if a network is WPA2-Enterprise or WPA3-Enterprise
    wpa2 = {1, 3, 5}
    wpa3 = {8, 9}
    if any(a in wpa3 for a in akm_list):
        return 'WPA3-Enterprise'
    if any(a in wpa2 for a in akm_list):
        return 'WPA2-Enterprise'
    return 'Unknown EAP version or PSK authentication used'


def mfp_required(cap):
    # Check if Management Frame Protection is required
    return bool(cap and (cap & 0x0080))


def process_packet(pkt):
    # Process each packet to extract EAP, EAPOL and network configuration information
    
    # Process beacons and probe responses to extract RSN information
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ssid = pkt[Dot11Elt].info.decode(errors='ignore')
        bssid = pkt[Dot11].addr3
        elt = pkt.getlayer(Dot11Elt, nb=1)
        while elt:
            # RSN Information Element (ID 48)
            if elt.ID == 48:
                try:
                    info = parse_rsn_info(elt.info)
                except Exception:
                    break
                key = (ssid, bssid)
                net = networks[key]
                net['group']    = info['group_cipher']
                net['pairwise'] |= set(info['pairwise_ciphers'])
                net['akms']     |= set(info['akm_types'])
                net['caps']      = info['capabilities']
                break
            elt = elt.payload.getlayer(Dot11Elt)

    # Process EAPOL packets
    if pkt.haslayer(EAPOL):
        if pkt.haslayer(Dot11):
            bssid = pkt[Dot11].addr3 or '<unknown>'
        else:
            bssid = pkt.src if hasattr(pkt, 'src') else '<unknown>'
        matches = [k for k in networks if k[1].lower() == bssid.lower()]
        if not matches:
            matches = [('<unknown>', bssid)]
        for key in matches:
            net = networks[key]
            if pkt.haslayer(EAP):
                e = pkt.getlayer(EAP)
                if isinstance(e.type, int):
                    net['eap_types'].add(int(e.type))
            else:
                net['seen_eapol'] = True
        return

    # Process standalone EAP packets
    if pkt.haslayer(EAP):
        if pkt.haslayer(Dot11):
            bssid = pkt[Dot11].addr3 or '<unknown>'
        else:
            bssid = pkt.src if hasattr(pkt, 'src') else '<unknown>'
        key = ('<unknown>', bssid)
        e = pkt.getlayer(EAP)
        if isinstance(e.type, int):
            networks[key]['eap_types'].add(int(e.type))


def get_help():
    # Return help information structure for the command-line interface
    return [
        {"description": ["Inspect EAP-Enterprise parameters in wireless networks"]},
        {"usage": ["pteapinspector <options>"]},
        {"usage_example": [
            "pteapinspector -f file.pcap",
            "pteapinspector -i wlan0mon -t 60",
        ]},
        {"options": [
            ["-f",  "--file",            "<file>",      "PCAP file to load"],
            ["-i",  "--iface",           "<interface>", "Monitor-mode interface (live capture)"],
            ["-t",  "--time",            "<seconds>",   "Capture duration (s) [required with -i]"],
            ["-b",  "--bssid",           "<bssid>",     "Filter by target BSSID (optional)"],
            ["-c",  "--current-channel", "<channel>",   "Channel to tune interface to (optional)"],
            ["-v",  "--version",         "",             "Show script version and exit"],
            ["-h",  "--help",            "",             "Show this help message and exit"],
            ["-j",  "--json",            "",             "Output in JSON format"],
        ]}
    ]


def parse_args():
    # Parse and validate command-line arguments
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    pre_args, remaining = pre.parse_known_args()
    if pre_args.help:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        raise SystemExit(0)
        
    parser = argparse.ArgumentParser(description='Inspect EAP-Enterprise parameters in WPA2/3 networks')
    mex = parser.add_mutually_exclusive_group(required=True)
    mex.add_argument('-f', '--file', help='PCAP file to load')
    mex.add_argument('-i', '--iface', help='Monitor-mode interface (live capture)')
    parser.add_argument('-t', '--time', type=int, help='Capture duration (s) [required with -i]')
    parser.add_argument('-b', '--bssid', help='Filter by target BSSID (optional)')
    parser.add_argument('-c', '--current-channel', type=int, help='Channel to tune interface to (optional)')
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
    parser.add_argument('-v', '--version', action='version', version=f'{SCRIPTNAME} {__version__}')
    
    args = parser.parse_args(remaining)
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    
    # Validate interface + duration requirement
    if args.iface and args.time is None:
        ptjsonlib_object.end_error(
            "Capture duration (--time) is required when using a live interface",
            args.json
        )
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "pteapinspector"

    args = parse_args()

    # Tune interface if required
    tune_interface(args.iface, args.current_channel)

    # Capture packets from file or interface
    capture_packets(args)

    # Print console summary
    if not print_summary(networks, args):
        ptprint('No networks with EAP types found in capture.',
                bullet_type="INFO", condition=not args.json)

    # Generate vulnerability reports for JSON output
    if args.json:
        add_mfp_vuln(networks, args.json)
        add_legacy_eap_vulns(networks)

    # Finalize execution
    ptprint(f'\nDone.', bullet_type="OK", condition=not args.json)
    ptjsonlib_object.set_status("finished")
    ptprint(ptjsonlib_object.get_result_json(), "", args.json)


if __name__ == '__main__':
    main()
