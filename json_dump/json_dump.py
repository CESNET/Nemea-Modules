#!/usr/bin/python3

import argparse
import io
import json
import socket
import sys
import time
from typing import Optional

import pytrap


def get_parser() -> argparse.ArgumentParser:
    """Prepare the argument parser.

    Returns:
         An instance of ArgumentParser with ready arguments.
    """
    parser = argparse.ArgumentParser(add_help=True)
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

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-w", dest="filename", metavar="FILE",
                       help="Write dump to FILE instead of stdout (overwrite file)")
    group.add_argument("-a", dest="filename_append", metavar="FILE",
                       help="Write dump to FILE instead of stdout (append to file)")
    group.add_argument("-s", dest="networktarget", metavar="HOST:PORT",
                       help="Write dump using a TCP network stream to HOST:PORT")
    return parser


def connect_socket(address: str, port: int) -> socket.SocketIO:
    """Create a connection to a socket given an address and a port.

    The connection is tried repeatedly until successful. If the connection to the socket
    fails, wait 5 seconds and retry.

    Args:
        address (str): The address of the destination socket.
        port (int): The port of the destination socket.

    Returns:
        The SocketIO object.
    """
    while True:
        try:
            s = socket.create_connection((address, port))
            sys.stderr.write(time.strftime("%F-%T") +
                             f" Connection to {address}:{port} established.\n")
            sys.stderr.flush()
            return socket.SocketIO(s, "w")
        except socket.error:
            # sleep for a while and then reconnect
            sys.stderr.write(time.strftime("%F-%T") +
                             " Connection failed, trying again in 5 seconds.\n")
            sys.stderr.flush()
            time.sleep(5)


def main():
    parser = get_parser()
    parsed_args = parser.parse_args()

    address: Optional[str] = None
    port: Optional[int] = None

    # Parsing the arguments
    if parsed_args.filename:
        file = io.FileIO(parsed_args.filename, "w")
    elif parsed_args.filename_append:
        file = io.FileIO(parsed_args.filename_append, "a")
    elif parsed_args.networktarget:
        addr = parsed_args.networktarget.split(":")
        if len(addr) != 2:
            raise argparse.ArgumentError(argument=None,
                                         message="Malformed argument of -s host:port")
        address = addr[0]
        port = int(addr[1])
        file = connect_socket(address, port)
    else:
        file = sys.stdout

    # Initialize the PyTrap module
    trap = pytrap.TrapCtx()
    trap.init(["-i", parsed_args.ifcspec])

    # Set JSON as required data type on input
    trap.setRequiredFmt(0, pytrap.FMT_JSON, "")

    stop = False
    # Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
    while not stop:
        # Read data from input interface
        try:
            data = trap.recv()
        except pytrap.FormatMismatch:
            sys.stderr.write(
                "Error: output and input interfaces data type or format mismatch\n")
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

        try:
            # Decode data (and check it's valid JSON)
            rec = json.loads(data.decode("utf-8"))
            if parsed_args.verbose:
                print(f"Message: {format(rec)}")
            # Print it to file or stdout
            file.write(bytes(json.dumps(rec, indent=parsed_args.indent) + '\n', "utf-8"))
            if not parsed_args.noflush:
                file.flush()
        except ValueError as e:
            sys.stderr.write(str(e) + '\n')
            sys.stderr.flush()
        except BrokenPipeError:
            if parsed_args.networktarget:
                file = connect_socket(address, port)
                file.write(
                    bytes(json.dumps(rec, indent=parsed_args.indent) + '\n', "utf-8"))
                if not parsed_args.noflush:
                    file.flush()


if __name__ == "__main__":
    main()
