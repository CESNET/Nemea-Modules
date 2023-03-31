#!/usr/bin/python3

import argparse
import io
import json
import socket
import sys
import time
from typing import Optional, TextIO

import pytrap


def get_parser() -> argparse.ArgumentParser:
    """Prepare the argument parser.

    Returns:
         An instance of ArgumentParser with ready arguments.
    """
    parser = argparse.ArgumentParser(description="Print received JSON messages to stdout or a file.")
    parser.add_argument("-i", "--ifcspec", dest="ifcspec", metavar="IFCSPEC",
                        required=True,
                        help="See https://nemea.liberouter.org/trap-ifcspec/")
    parser.add_argument("-I", "--indent", metavar="N", type=int,
                        help="Pretty-print JSON with indentation set to N spaces. "
                             "Note that such format can't be read by json_replay module.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Set verbose mode (print messages).")
    parser.add_argument("--noflush", action="store_true",
                        help="Disable automatic flush of output buffer after writing a "
                             "record (may improve performance).")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-w", dest="filename", metavar="FILE",
                       help="Write data to FILE instead of stdout (overwrite file)")
    group.add_argument("-a", dest="filename_append", metavar="FILE",
                       help="Write data to FILE instead of stdout (append to file)")
    group.add_argument("-s", dest="networktarget", metavar="HOST:PORT",
                       help="Send data using a TCP network stream to HOST:PORT")
    return parser


def connect_socket(address: str, port: int, wait_interval: int = 5) -> TextIO:
    """Create a connection to a socket given an address and a port.

    The connection is tried repeatedly until successful. If the connection to the socket
    fails, wait 5 seconds and retry.

    Args:
        address (str): The address of the destination socket.
        port (int): The port of the destination socket.
        wait_interval (int): Number of seconds to wait before retrying connection if it fails (default: 5 sec)

    Returns:
        TextIO object providing access to opened socket.
    """
    last_error = None
    while True:
        if last_error is None:
            print(f"{time.strftime('%F-%T')} Connecting to {address}:{port} ...", file=sys.stderr)
        try:
            s = socket.create_connection((address, port))
            print(f"{time.strftime('%F-%T')} Connection established.", file=sys.stderr)
            last_error = None
            return s.makefile("w", encoding="utf-8")
        except OSError as e:
            # sleep for a while and then reconnect (print error only once or when the error message changes)
            if last_error is None or str(e) != last_error:
                print(f"{time.strftime('%F-%T')} Connection failed ({e}), retrying every {wait_interval} seconds ...", file=sys.stderr)
                last_error = str(e)
            time.sleep(wait_interval)


def main():
    parser = get_parser()
    parsed_args = parser.parse_args()

    address: Optional[str] = None
    port: Optional[int] = None

    # Parsing the arguments
    if parsed_args.filename:
        file = open(parsed_args.filename, "w", encoding="utf-8")
    elif parsed_args.filename_append:
        file = open(parsed_args.filename_append, "a", encoding="utf-8")
    elif parsed_args.networktarget:
        try:
            address, port = parsed_args.networktarget.split(":")
            port = int(port)
        except (TypeError, ValueError):
            print("Error: malformed argument of -s host:port", file=sys.stderr)
            sys.exit(1)
        file = connect_socket(address, port)
    else:
        file = sys.stdout

    # Initialize the PyTrap module
    trap = pytrap.TrapCtx()
    trap.init(["-i", parsed_args.ifcspec])

    # Set JSON as required data type on input
    trap.setRequiredFmt(0, pytrap.FMT_JSON, "")

    # Main loop
    while True:
        # Read data from input interface
        try:
            data = trap.recv()
        except pytrap.FormatMismatch:
            print("Error: output and input interfaces data type or format mismatch", file=sys.stderr)
            break
        except pytrap.FormatChanged as e:
            if parsed_args.verbose:
                print(trap.getDataFmt(0))
            data = e.data
        except (pytrap.Terminated, KeyboardInterrupt):
            break

        # Check for "end-of-stream" record
        if len(data) <= 1:
            if parsed_args.verbose:
                print('Received "end-of-stream" message, going to quit.')
            break

        # Decode data (and check it's valid JSON)
        try:
            rec = json.loads(data.decode("utf-8"))
        except ValueError as e:
            print(f"ERROR: Received invalid JSON (message skipped): {e}", file=sys.stderr)
            continue

        if parsed_args.verbose:
            print(f"Message: {format(rec)}")

        # Print it to file, stdout, or send to socket
        try:
            file.write(json.dumps(rec, indent=parsed_args.indent) + '\n')
            if not parsed_args.noflush:
                file.flush()
        except IOError as e:
            if parsed_args.networktarget:
                print(f"{time.strftime('%F-%T')} Connection error: {e}", file=sys.stderr)
                # connection error, try to reconnect and send the message again
                file = connect_socket(address, port)
                file.write(json.dumps(rec, indent=parsed_args.indent) + '\n')
                if not parsed_args.noflush:
                    file.flush()
            else:
                raise


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass # quietly exit program without traceback
