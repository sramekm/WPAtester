#!/usr/bin/env python3

import argparse
import sys
sys.path.append(__file__.rsplit("/", 1)[0])

from modules.scan_module import scan
from modules.attack_module import attack
from ptlibs import ptprinthelper
from _version import __version__

# Define the script name at module level
SCRIPTNAME = "ptdowngrade"

def get_help():
    # Return a structured help menu for the tool
    return [
        {"description": ["WPA3 personal transition mode discovery & attack toolkit"]},
        {"usage": ["ptdowngrade <command> <options>"]},
        {"usage_example": [
            "ptdowngrade scan -i wlan0mon -t 15",
            "ptdowngrade scan -f test.pcap",
            "ptdowngrade attack -i wlan0mon -R wlan1 -s testnet -m aa:bb:cc:dd:ee:ff -c 6"
        ]},
        {"Scan module options": [
            ["-i", "--iface", "<interface>", "Monitor-mode interface"],
            ["-f", "--file", "<file>", "PCAP file to load (skips live capture)"],
            ["-t", "--time", "<seconds>", "Capture duration in seconds"],
            ["-b", "--bssid", "<bssid>", "Only scan this BSSID"],
            ["-c", "--channel", "<channel>", "Restrict scan to a single channel (default: all)"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"]
        ]},
        {"Attack module options": [
            ["-i", "--iface", "<interface>", "Monitor-mode interface"],
            ["-R", "--rogue-iface", "<interface>", "Interface to host rogue AP"],
            ["-s", "--ssid", "<ssid>", "SSID of the vulnerable AP"],
            ["-m", "--client-mac", "<mac>", "MAC of the target client"],
            ["-c", "--channel", "<channel>", "Channel of the vulnerable AP"],
            ["-o", "--output-folder", "<dir>", "Output directory for hostapd config and handshake files"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"]
        ]}
    ]

def parse_args():
    # Parse command line arguments and return the parsed args
    parser = argparse.ArgumentParser(prog=SCRIPTNAME, description="WPA3 personal transition mode discovery & attack toolkit")

    parser.add_argument("-j", "--json", action="store_true", help="Output in JSON format")
    parser.add_argument("-v", "--version", action='version', version=f'{SCRIPTNAME} {__version__}')

    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)

    # SCAN subcommand
    p_scan = subparsers.add_parser("scan", help="Discover vulnerable APs via airodump-ng")
    p_scan.add_argument("-i", "--iface", help="Monitor-mode interface")
    p_scan.add_argument("-f", "--file", help="PCAP file to load (skips live capture)")
    p_scan.add_argument("-t", "--time", type=int, help="Capture duration in seconds")
    p_scan.add_argument("-b", "--bssid", help="Only scan this BSSID")
    p_scan.add_argument("-c", "--channel", type=int, help="Restrict scan to a single channel (default: all)")
    p_scan.set_defaults(func=scan)

    # ATTACK subcommand
    p_attack = subparsers.add_parser("attack", help="Launch rogue AP & capture handshake")
    p_attack.add_argument("-i", "--iface", required=True, help="Monitor-mode interface")
    p_attack.add_argument("-R", "--rogue-iface", required=True, help="Interface to host rogue AP")
    p_attack.add_argument("-s", "--ssid", required=True, help="SSID of the vulnerable AP")
    p_attack.add_argument("-m", "--client-mac", required=True, help="MAC of the target client")
    p_attack.add_argument("-c", "--channel", type=int, required=True, help="Channel of the vulnerable AP")
    p_attack.add_argument("-o", "--output-folder", default=None, help="Output directory for hostapd config and handshake files")
    p_attack.set_defaults(func=attack)

    # Show help if no arguments or help flag is provided
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args

def main():
    # Main entry point of the program
    args = parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
