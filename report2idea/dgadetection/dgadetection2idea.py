#!/usr/bin/python3

# In case we are in nemea/modules/report2idea/bruteforce and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *
import socket


# Moudle name, description and required input data format
MODULE_NAME = "dgadetection"
MODULE_DESC = "Converts output of DGA_detector module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr SRC_IP,ipaddr DST_IP,time TIME_FIRST,time TIME_LAST,string DNS_Q_NAME"


# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    
    """
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "DetectTime": getIDEAtime(rec.TIME_LAST),
        #"CreateTime": getIDEAtime(),
        "Category": [ "Intrusion.Botnet","test" ],
        "Description": "Botnet trying to comunicate with control server using DGA",
        "Source": [{
            #"IP4": [rec.SRC_IP]
         }],
        "Target": [{    
            #"IP4": [rec.DST_IP],
            "Hostname": [rec.DNS_Q_NAME]
        }],
        'Node': [{
            'SW': [ 'Nemea', 'DGA_detector' ]
        }],
    }
    setAddr(idea['Source'][0], rec.SRC_IP)
    setAddr(idea['Target'][0], rec.DST_IP)
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

