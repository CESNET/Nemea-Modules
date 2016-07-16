#!/usr/bin/env python

from __future__ import absolute_import

from report2idea import *
import argparse

# Module parameters
MODULE_NAME = "idea2idea"
MODULE_DESC = "Pass IDEA message unchanged (for testing and debugging purposes)"
REQ_TYPE = trap.TRAP_FMT_JSON
REQ_FORMAT = "IDEA"

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Main conversion function
    rec - Record recevied on TRAP input interface (the report to convert). Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)
    Return report in IDEA format (as Python dict)
    """
    return rec


# Run the module
if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = None
    )
