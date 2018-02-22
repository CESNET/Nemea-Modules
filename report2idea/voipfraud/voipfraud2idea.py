#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/voipfraud and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "voipfraud2idea"
MODULE_DESC = "Converts output of voip_fraud_detection module to IDEA."
REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,time DETECTION_TIME,time TIME_FIRST,uint32 EVENT_ID,uint32 VOIP_FRAUD_INVITE_COUNT,uint32 VOIP_FRAUD_PREFIX_EXAMINATION_COUNT,uint32 VOIP_FRAUD_SUCCESSFUL_CALL_COUNT,uint16 VOIP_FRAUD_PREFIX_LENGTH,uint8 EVENT_TYPE,string VOIP_FRAUD_COUNTRY_CODE,string VOIP_FRAUD_SIP_FROM,string VOIP_FRAUD_SIP_TO,string VOIP_FRAUD_USER_AGENT"

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """

    # EVT_T_VOIP_PREFIX_GUESS is defined as EVENT_TYPE == 40
    if rec.EVENT_TYPE != 40:
        # skip other alerts
        return None
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(),
        "DetectTime": getIDEAtime(rec.DETECTION_TIME),
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "Category": [ "Attempt.Login" ],
        "Description": "SIP Dial-plan guessing",
        "ConnCount": rec.VOIP_FRAUD_INVITE_COUNT,
        "MaxPrefixLength": rec.VOIP_FRAUD_PREFIX_LENGTH,
        "TriedPrefixCount": rec.VOIP_FRAUD_PREFIX_EXAMINATION_COUNT,
        "SuccessfulCalls": rec.VOIP_FRAUD_SUCCESSFUL_CALL_COUNT,
        "Source": [{
            "Proto": ["sip"],
            "UserAgent": [ rec.VOIP_FRAUD_USER_AGENT ],
            "SIPFrom": [ rec.VOIP_FRAUD_SIP_FROM ]
        }],
        "Target": [{
            "Proto": ["sip"],
            "SIPTo": [ rec.VOIP_FRAUD_SIP_TO ]
        }],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'voip_fraud_detection' ],
            'Type': [ 'Flow', 'Statistical', 'Content' ],
        }]
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

