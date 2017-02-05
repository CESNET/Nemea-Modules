#!/usr/bin/env python

from __future__ import absolute_import

# In case we are in nemea/modules/report2idea/hoststats and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

from report2idea import *
import argparse
import re

# Module parameters
MODULE_NAME = "hoststats2idea"
MODULE_DESC = "Converts output of HostStatsNemea module to IDEA."
REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "uint8 EVENT_TYPE,time TIME_FIRST,time TIME_LAST,ipaddr SRC_IP,ipaddr DST_IP,uint8 PROTOCOL,uint32 EVENT_SCALE,string NOTE"

# Event type contants (from old "unirec/fields" file)
EVT_T_PORTSCAN                    =  1  # Portscan (unspecified type)
EVT_T_PORTSCAN_H                  =  2  # Horizontal portscan (one or a few ports, many addresses)
EVT_T_PORTSCAN_V                  =  3  # Vertical portscan (one address, many ports)
EVT_T_DOS                         = 10  # Denial of service attack (unspecified type)
EVT_T_SYNFLOOD                    = 11  # TCP SYN flood
EVT_T_DNSAMP                      = 15  # DNS Amplification attack
EVT_T_BRUTEFORCE                  = 30  # Bruteforce password guessing


# Auxiliary function
proto_conv = {
    1 : 'icmp',
    6 : 'tcp',
    17 : 'udp',
}

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Main conversion function
    rec - Record recevied on TRAP input interface (the report to convert). Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)
    Return report in IDEA format (as Python dict)
    """
    def VERBOSE(msg):
        if opts.verbose:
            print(MODULE_NAME+": "+msg)
    
    # Set fields which are always present
    createTime = getIDEAtime()
    idea = {
        'Format': 'IDEA0',
        'ID': getRandomId(),
        'DetectTime': createTime,
        'CreateTime': createTime,
        'EventTime': getIDEAtime(rec.TIME_FIRST),
        'CeaseTime': getIDEAtime(rec.TIME_LAST),
        'Node': [{
            'Name': 'undefined', # this will be filled by common part
            'SW': ['Nemea','HostStatsNemea'],
            'Type': ['Flow', 'Statistical'],
            #'AggrWin': '00:05:00',
        }],
    }


    # Set remaining fields based on particular event type
    # Portscan (horizontal)
    if rec.EVENT_TYPE == EVT_T_PORTSCAN_H:
        idea['Category'] = ['Recon.Scanning']
        idea['Description'] = 'Horizontal port scan'
        
        idea['Source'] = [{}]
        setAddr(idea['Source'][0], rec.SRC_IP)
        if rec.PROTOCOL in proto_conv:
            idea['Source'][0]['Proto'] = [proto_conv[rec.PROTOCOL]]
        
        idea['FlowCount'] = rec.EVENT_SCALE  # number of outgoing SYNs minus outgoing ACKs
        idea['ConnCount'] = rec.EVENT_SCALE  # number of outgoing SYNs minus outgoing ACKs
      
    # DNS Amplification
    elif rec.EVENT_TYPE == EVT_T_DNSAMP:
        idea['Category'] = ['Availability.DoS']
        
        if rec.DST_IP:
            idea['Target'] = [{
                'Proto': ['udp', 'dns'],
            }]
            setAddr(idea['Target'][0], rec.DST_IP)
            idea['Description'] = str(rec.DST_IP)+' received abnormally high number of large DNS replies - probably a victim of DNS amplification DoS attack'
        if rec.SRC_IP:
            idea['Source'] = [{
                'Type': ['Backscatter'],
                'Port': [53],
                'Proto': ['udp', 'dns'],
            }]
            setAddr(idea['Source'][0], rec.SRC_IP)
            idea['Description'] = str(rec.SRC_IP)+' sent abnormally high number of large DNS replies - it was probably misused for DNS amplification DoS attack'
        
        idea['FlowCount'] = rec.EVENT_SCALE  # number of incoming replies greater than limit (currently 1000B)
      
    # DoS
    elif rec.EVENT_TYPE == EVT_T_DOS:
        idea['Category'] = ['Availability.DoS']
         
        if rec.DST_IP:
            idea['Target'] = [{}]
            setAddr(idea['Target'][0], rec.DST_IP)
            if rec.PROTOCOL in proto_conv:
                idea['Target'][0]['Proto'] = [proto_conv[rec.PROTOCOL]]
         
        if rec.SRC_IP:
            idea['Source'] = [{}]
            setAddr(idea['Source'][0], rec.SRC_IP)
            if rec.PROTOCOL in proto_conv:
                idea['Source'][0]['Proto'] = [proto_conv[rec.PROTOCOL]]
         
        idea['FlowCount'] = rec.EVENT_SCALE  # number of incoming or outgoing flows
         
        # Description
        if 'Target' in idea: # victim
            if rec.PROTOCOL == 6:
                idea['Description'] = 'Abnormally high number of TCP SYN packets received by '+str(rec.DST_IP)+' (probably SYN flood attack)'
            else:
                idea['Description'] = 'Abnormally high number of packets received by '+str(rec.DST_IP)+' (probably flooding DoS attack)'
        elif 'Source' in idea: # attacker
            if rec.PROTOCOL == 6:
                idea['Description'] = 'Abnormally high number of TCP SYN packets emitted by '+str(rec.SRC_IP)+' (probably SYN flood attack)'
            else:
                idea['Description'] = 'Abnormally high number of packets emmited by '+str(rec.SRC_IP)+' (probably flooding DoS attack)'
         
        # Parse information from NOTE (victim)
        match = re.match(
            "in: (\d+) flows, (\d+) packets; out: (\d+) flows, (\d+) packets; approx. (\d+) source addresses.*",
            rec.NOTE
        )
        if match and 'Target' in idea:
            idea['Target'][0]['InFlowCount'] = int(match.group(1))
            idea['Target'][0]['InPacketCount'] = int(match.group(2))
            idea['Target'][0]['OutFlowCount'] = int(match.group(3))
            idea['Target'][0]['OutPacketCount'] = int(match.group(4))
            if 'Source' not in idea:
                idea['Source'] = [{}]
            idea['Source'][0]['Count'] = int(match.group(5))
            idea['Source'][0]['Note'] = 'Count of sources is approximate'
        
        # Parse information from NOTE (attacker)
        match = re.match(
            "out: (\d+) flows, (\d+) packets; in: (\d+) flows, (\d+) packets; approx. (\d+) destination addresses.*",
            rec.NOTE
        )
        if match and 'Source' in idea:
            idea['Source'][0]['OutFlowCount'] = int(match.group(1))
            idea['Source'][0]['OutPacketCount'] = int(match.group(2))
            idea['Source'][0]['InFlowCount'] = int(match.group(3))
            idea['Source'][0]['InPacketCount'] = int(match.group(4))
            if 'Target' not in idea:
                idea['Target'] = [{}]
            idea['Target'][0]['Count'] = int(match.group(5))
            idea['Target'][0]['Note'] = 'Count of destinations is approximate'
               
    # SSH Bruteforce
    elif rec.EVENT_TYPE == EVT_T_BRUTEFORCE:
        idea['Category'] = ['Attempt.Login']
        idea['Description'] = 'SSH dictionary/bruteforce attack'
         
        idea['Target'] = [{
            'Port': [22],
            'Proto': ['tcp','ssh'],
        }]
        if rec.DST_IP:
            setAddr(idea['Target'][0], rec.DST_IP)
        if rec.SRC_IP:
            idea['Source'] = [{}]
            setAddr(idea['Source'][0], rec.SRC_IP)
         
        idea['FlowCount'] = 2 * rec.EVENT_SCALE  # number of flows (two flows per connection)
        idea['ConnCount'] = rec.EVENT_SCALE  # number of tries
      
    # Unknown event type
    else:
        VERBOSE("Skipping event of unknown type (%u)." % rec.EVENT_TYPE)
        return None
    
    return idea


# Run the module
if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = None # (optional) Instance of argparse.ArgumentParser with some arguments defined can be passed - these arguments are then parsed from command line and passed to the conv_func)
    )

