#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/sipbruteforce and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *
import socket


# Moudle name, description and required input data format
MODULE_NAME = "sipbf2idea"
MODULE_DESC = "Converts output of sip_bf_detector module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "uint64 SBFD_EVENT_ID,uint8 SBFD_EVENT_TYPE,ipaddr SBFD_TARGET,ipaddr SBFD_SOURCE,string SBFD_USER,uint64 SBFD_LINK_BIT_FIELD,uint8 SBFD_PROTOCOL,time SBFD_EVENT_TIME,time SBFD_CEASE_TIME,time SBFD_BREACH_TIME,uint32 SBFD_ATTEMPTS,uint32 SBFD_AVG_ATTEMPTS,uint16 SRC_PORT,uint16 DST_PORT"

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """
    #if rec.WARDEN_TYPE != 2:
    #    # this alert is not bruteforce
    #    return None
    time = getIDEAtime();
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "DetectTime": time,
        "CreateTime": time,
        "EventTime": getIDEAtime(rec.SBFD_EVENT_TIME),
        "CeaseTime": getIDEAtime(rec.SBFD_CEASE_TIME),
        "ConnCount": rec.SBFD_ATTEMPTS,
        "Source": [{
            "Proto": [ "sip" ],
            "Port": [rec.SRC_PORT]
         }],
        "Target": [{
            "Proto": [ "sip" ],
            "Port": [rec.DST_PORT]
         }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'brute_force_detector' ],
            'Type': [ 'Flow', 'Statistical' ]
        }],
    }
    if rec.SBFD_EVENT_TYPE == 0:
        # brute-force
        idea["Category"] = [ "Attempt.Login" ]
        idea["Description"] = "SIP BruteForce login attempt, user account: " + rec.SBFD_USER
        if rec.SBFD_BREACH_TIME != pytrap.UnirecTime(0):
            idea["BreachTime"] = getIDEAtime(rec.SBFD_BREACH_TIME)
            idea["Description"] = "Successful " + idea["Description"]

    elif rec.SBFD_EVENT_TYPE == 1:
        # distributed brute-force
        idea["Category"] = [ "Attempt.Login" ]
        idea["Description"] = "distributed SIP BruteForce login attempt, user account: " + rec.SBFD_USER
        if rec.SBFD_BREACH_TIME != pytrap.UnirecTime(0):
            idea["BreachTime"] = getIDEAtime(rec.SBFD_BREACH_TIME)
            idea["Description"] = "Successful " + idea["Description"]
        else:
            idea["Description"][0] = "D"
    elif rec.SBFD_EVENT_TYPE == 2:
        # scan
        idea["Category"] = [ "Recon.Scanning" ]
        idea["Description"] = "Scan of SIP user accounts"

    setAddr(idea['Source'][0], rec.SBFD_SOURCE)
    setAddr(idea['Target'][0], rec.SBFD_TARGET)
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

