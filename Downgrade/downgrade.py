#!/usr/bin/env python3

import argparse
from scan_module import scan
from attack_module import attack


def parse_args():
    parser = argparse.ArgumentParser(
        prog="dragonshift",
        description="WPA3 Dragonblood discovery & attack toolkit"
    )
    subparsers = parser.add_subparsers(
        title="Commands", dest="command", required=True
    )

    # SCAN subcommand (unchanged)
    p_scan = subparsers.add_parser(
        "scan", help="Discover vulnerable APs via airodump-ng"
    )
    p_scan.add_argument(
        "-i", "--iface", help="Monitor-mode interface"
    )
    p_scan.add_argument(
        "-f", "--file", help="PCAP file to load (skips live capture)"
    )
    p_scan.add_argument(
        "-t", "--time", type=int, help="Capture duration in seconds"
    )
    p_scan.add_argument(
        "-b", "--bssid", help="Only scan this BSSID"
    )
    p_scan.add_argument(
        "-c", "--channel", type=int,
        help="Restrict scan to a single channel (default: all)"
    )
    p_scan.set_defaults(func=scan)

    # ATTACK subcommand (flags renamed & parse_args extracted)
    p_attack = subparsers.add_parser(
        "attack", help="Launch rogue AP & capture handshake"
    )
    p_attack.add_argument(
        "-i", "--iface", required=True,
        help="Monitor-mode interface"
    )
    p_attack.add_argument(
        "-R", "--rogue-iface", required=True,
        help="Interface to host rogue AP"
    )
    p_attack.add_argument(
        "-s", "--ssid", required=True,
        help="SSID of the vulnerable AP"
    )
    p_attack.add_argument(
        "-m", "--client-mac", required=True,
        help="MAC of the target client"
    )
    p_attack.add_argument(
        "-c", "--channel", type=int, required=True,
        help="Channel of the vulnerable AP"
    )
    p_attack.add_argument(
        "-o", "--output-folder", default=None,
        help="Output directory for hostapd config and handshake files"
    )
    p_attack.set_defaults(func=attack)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
