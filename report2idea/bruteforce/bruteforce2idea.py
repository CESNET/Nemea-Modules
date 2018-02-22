#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/bruteforce and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *
import socket


# Moudle name, description and required input data format
MODULE_NAME = "bruteforce2idea"
MODULE_DESC = "Converts output of brute_force_detector module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr SRC_IP,time DETECTION_TIME,uint32 EVENT_SCALE,uint16 DST_PORT,uint8 PROTOCOL,uint8 WARDEN_TYPE"

# Auxiliary function
proto_conv = {
    1 : 'icmp',
    6 : 'tcp',
    17 : 'udp',
}

def getServiceName(port, proto):
    service = ""
    servName = { 22: "SSH",
                 23: "TELNET",
                 2179: "VMRDP",
                 5900: "VNC" }
    try:
        service = servName[port]
    except KeyError:
        try:
            service = socket.getservbyport(port, proto).upper()
        except socket.error:
            pass
    return service

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
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "DetectTime": getIDEAtime(rec.DETECTION_TIME),
        "CreateTime": getIDEAtime(),
        "Category": [ "Attempt.Login" ],
        "Description": "Multiple unsuccessful login attempts" + (" on {0}".format(service) if service else ""),
        "FlowCount": rec.EVENT_SCALE,
        "Source": [{
            "Proto": [ proto_conv[rec.PROTOCOL], service.lower() ] if service else [ proto_conv[rec.PROTOCOL] ]
         }],
        "Target": [{
            "Port": [rec.DST_PORT],
            "Proto": [ proto_conv[rec.PROTOCOL], service.lower() ] if service else [ proto_conv[rec.PROTOCOL] ]
         }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'brute_force_detector' ],
            'Type': [ 'Flow', 'Statistical' ]
        }],
    }
    setAddr(idea['Source'][0], rec.SRC_IP)
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

