#!/usr/bin/env python3
import argparse
import subprocess
import struct
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
    50: 'PWD',      # some implementations
    52: 'PWD',      # as Wireshark shows
    43: 'FAST',
}

def parse_rsn_info(info_bytes):
    """
    Parse raw RSN IE per IEEE-802.11 into:
      - group_cipher (int)
      - pairwise_ciphers (list[int])
      - akm_types (list[int])
      - capabilities (int or None)
    """
    pos = 0
    # version
    pos += 2
    # group cipher suite: 3-byte OUI + 1-byte type
    pos += 3
    group_cipher = info_bytes[pos]
    pos += 1

    # pairwise ciphers
    pairwise_count = struct.unpack_from('<H', info_bytes, pos)[0]
    pos += 2
    pairwise = []
    for _ in range(pairwise_count):
        pos += 3
        pairwise.append(info_bytes[pos])
        pos += 1

    # AKM suites
    akm_count = struct.unpack_from('<H', info_bytes, pos)[0]
    pos += 2
    akms = []
    for _ in range(akm_count):
        pos += 3
        akms.append(info_bytes[pos])
        pos += 1

    # optional RSN capabilities
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
    """WPA3-Enterprise if any AKM in {8,9}, else WPA2 if in {1,3,5}, else unknown."""
    wpa2 = {1, 3, 5}
    wpa3 = {8, 9}
    if any(a in wpa3 for a in akm_list):
        return 'WPA3-Enterprise'
    if any(a in wpa2 for a in akm_list):
        return 'WPA2-Enterprise'
    return 'Unknown EAP version or PSK authentication'

def mfp_required(cap):
    """802.11w MFP required if RSN-capabilities bit 0x0080 set."""
    return bool(cap and (cap & 0x0080))

# Data structure: networks[(ssid,bssid)] → info dict
networks = defaultdict(lambda: {
    'group':       None,
    'pairwise':    set(),
    'akms':        set(),
    'caps':        None,
    'eap_types':   set(),
    'seen_eapol':  False,
})

def process_packet(pkt):
    # ——— RSN IE from Beacon/ProbeResp ———
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ssid = pkt[Dot11Elt].info.decode(errors='ignore')
        bssid = pkt[Dot11].addr3
        elt = pkt.getlayer(Dot11Elt, nb=1)
        while elt:
            if elt.ID == 48:  # RSN IE
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

    # ——— Any 802.1X/EAPOL, wireless or Ethernet ———
    if pkt.haslayer(EAPOL):
        # Determine BSSID (or Ethernet src MAC)
        if pkt.haslayer(Dot11):
            bssid = pkt[Dot11].addr3 or '<unknown>'
        else:
            bssid = pkt.src if hasattr(pkt, 'src') else '<unknown>'

        # Find existing networks with this BSSID
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

        # Done handling this packet
        return

    # ——— Pure EAP frames (no EAPOL) ———
    if pkt.haslayer(EAP):
        # Could be tunneled in another layer, or pure Ethernet EAP
        if pkt.haslayer(Dot11):
            bssid = pkt[Dot11].addr3 or '<unknown>'
        else:
            bssid = pkt.src if hasattr(pkt, 'src') else '<unknown>'
        key = ('<unknown>', bssid)
        e = pkt.getlayer(EAP)
        if isinstance(e.type, int):
            networks[key]['eap_types'].add(int(e.type))
        return

def main():
    parser = argparse.ArgumentParser(
        description='Inspect EAP-Enterprise parameters in WPA2/3 networks'
    )
    mex = parser.add_mutually_exclusive_group(required=True)
    mex.add_argument('-f', '--file', help='PCAP file to load')
    mex.add_argument('-i', '--iface', help='Monitor-mode interface (live capture)')
    parser.add_argument('-t', '--time', type=int,
                        help='Capture duration (s) [required with -i]')
    parser.add_argument('-b', '--bssid', help='Filter by target BSSID (optional)')
    parser.add_argument('-c', '--current-channel', type=int,
                        help='Channel to tune interface to (optional)')

    args = parser.parse_args()

    # Enforce --time with --iface
    if args.iface and args.time is None:
        parser.error('--time is required when capturing live traffic')

    # Auto-tune channel if requested
    if args.iface and args.current_channel:
        subprocess.run(
            ['iwconfig', args.iface, 'channel', str(args.current_channel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    # Load or capture
    try:
        if args.file:
            for pkt in rdpcap(args.file):
                process_packet(pkt)
        else:
            sniff(iface=args.iface, timeout=args.time,
                  prn=process_packet, store=0)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f'[!] Capture/parse error: {e}')

    # Reporting
    found_any = False
    for (ssid, bssid), info in networks.items():
        if args.bssid and bssid.lower() != args.bssid.lower():
            continue

        # Skip networks with no info
        if (info['group'] is None
            and not info['pairwise']
            and not info['akms']
            and not info['eap_types']
            and not info['seen_eapol']):
            continue

        found_any = True
        print('=' * 60)
        print(f'SSID:   {ssid}')
        print(f'BSSID:  {bssid}')

        # Enterprise type
        ent = detect_enterprise(info['akms'])
        print(f'Protocol version:        {ent}')

        # MFP
        print(f'MFP Required:      {"Yes" if mfp_required(info["caps"]) else "No"}')

        # Ciphers
        grp = info['group']
        grp_name = CIPHER_MAP.get(grp, f'Unknown({grp})')
        pw_names = [CIPHER_MAP.get(p, f'Unknown({p})')
                    for p in sorted(info['pairwise'])]
        print(f'Group cipher:     {grp_name}')
        print(f'Pairwise ciphers: {", ".join(pw_names) or "None"}')

        # EAP/EAPOL
        if info['eap_types']:
            entries = []
            for code in sorted(info['eap_types']):
                name = EAP_TYPE_MAP.get(code, 'Unknown')
                entries.append(f'{code} ({name})')
            print(f'EAP types seen:   {", ".join(entries)}')
        elif info['seen_eapol']:
            print('EAPOL frames present, but no EAP discovered → inner tunneling may be used')
        else:
            print('No EAP or EAPOL frames seen → unable to determine version')

    if not found_any:
        print('No RSN IE or EAP/EAPOL information found in capture.')

    print('\nDone.')

if __name__ == '__main__':
    main()
