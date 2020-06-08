#!/usr/bin/python3

# In case we are in nemea/modules/report2idea/sshbruteforceml and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *
import socket


# Moudle name, description and required input data format
MODULE_NAME = "sshbruteforceml"
MODULE_DESC = "Converts output of SSH bruteforce detector based on ML to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr SRC_IP,ipaddr DST_IP,uint16 DST_PORT,uint16 SRC_PORT,time EVENT_TIME"

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """
    if rec.WARDEN_TYPE != 2:
        # this alert is not bruteforce
        return None
    service = getServiceName(rec.DST_PORT, proto_conv[rec.PROTOCOL])
    source = rec.SRC_IP
    target = rec.DST_IP
    failcount = 1

    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "DetectTime": getIDEAtime(rec.DETECTION_TIME),
        "CreateTime": getIDEAtime(),
        "Category": [ "Attempt.Login" ],
        "Description": "Multiple unsuccessful SSH login attempts",
        "Note": f"Machine Learning model recognized {failcount} unsuccessful login attempts from {source} against SSH server {target}",
        "Source": [{
            "Proto": [ "tcp", "ssh" ]
         }],
        "Target": [{
            "Port": [rec.DST_PORT],
            "Proto": [ "tcp", "ssh" ]
         }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'sshbfdetectorml' ],
            'Type': [ 'Flow', 'Statistical' ]
        }],
    }
    setAddr(idea['Source'][0], source)
    setAddr(idea['Target'][0], target)
    return idea


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
#parser = argparse.ArgumentParser()

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

