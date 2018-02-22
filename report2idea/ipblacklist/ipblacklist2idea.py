#!/usr/bin/env python

# In case we are in nemea/modules/report2idea/ipblacklist and we want to import from repo:
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "nemea-framework", "pycommon"))

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "ipblacklist2idea"
MODULE_DESC = "Converts output of ipblacklistfilter module to IDEA."

REQ_TYPE = pytrap.FMT_UNIREC
REQ_FORMAT = "ipaddr DST_IP,ipaddr SRC_IP,uint8 PROTOCOL,uint16 SRC_PORT,uint16 DST_PORT,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST,time TIME_FIRST,time TIME_LAST,uint32 EVENT_SCALE,uint32 PACKETS"

# Blacklist ID to name lookup table (it is loaded from file specified by --blacklist-config in __main__)
bl_conv = {}

proto_conv = {
    1 : 'icmp',
    6 : 'tcp',
    17 : 'udp',
}

# Blacklist name (lowercase) to threshold lookup table (default is 1)
bl_scale_tholds = {
   'spamhaus' : '40',
   'tor' : '150',
}


def load_config(config):
    """Load `config` file of ipblacklistfilter module (bl_usrConfigFile.xml).
    This file contains a list of blacklists, their names and URLs.

    load_config() returns dictionary, where the key is id (= 2**ID from file) and
    value is a dictionary of "name", "type" and "source".
    """
    import xml.etree.ElementTree as xml
    bls = {}
    with open(config, "r") as f:
        tree = xml.parse(f)
    rootElement = tree.getroot()
    blacklists = list(list(list(rootElement)[0])[0])

    for struct in blacklists:
        elems = list(struct)
        bl_id = None
        bl_name = None
        bl_type = None
        bl_source = None
        for el in elems:
            attr = el.attrib["name"]
            if attr == "name":
                bl_name = el.text
            elif attr == "id":
                bl_id = 2**int(el.text)
            elif attr == "type":
                bl_type = el.text
            elif attr == "source":
                bl_source = el.text
        if not bl_id or not bl_name or not bl_type or not bl_source:
            sys.stderr.write("Incomplete configuration. " + str((bl_id, bl_name, bl_type)))
            break
        bls[bl_id] = {"name": bl_name, "type": bl_type, "source": bl_source}
    return bls

# Main conversion function
def convert_to_idea(rec, opts=None):
    """
    Get fields from UniRec message 'rec' and convert it into an IDEA message (Python dict()).

    rec - Record received on TRAP input interface (the report to convert).
          Its format satisfies what was defined by REQ_TYPE and REQ_FORMAT.
    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """
    global bl_conv, bl_scale_tholds

    if not bl_conv:
        bl_conv = load_config(opts.blacklist_config)

    endTime = getIDEAtime(rec.TIME_LAST)
    protocol = ""
    if rec.PROTOCOL in proto_conv:
        protocol = proto_conv[rec.PROTOCOL]
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": getIDEAtime(rec.TIME_FIRST),
        "DetectTime": endTime,
        'CeaseTime': endTime,
        "PacketCount": rec.PACKETS,
        "ByteCount": rec.BYTES,

        "Source": [],
        'Node': [{
            'Name': 'undefined',
            'SW': [ 'Nemea', 'ipblacklistfilter' ],
            'Type': [ 'Flow', 'Blacklist' ]
        }],
    }

    category = set()

    export = False
    tor = False
    blacklist = rec.SRC_BLACKLIST | rec.DST_BLACKLIST
    src_addr = {}
    dst_addr = {}
    src_entries = set()
    dst_entries = set()
    src_type = set()
    dst_type = set()
    sources = set()

    if rec.SRC_IP:
        src_addr = {
            "Proto": [ protocol ]
        }
        # Add Port for TCP (6) or UDP (17)
        if rec.PROTOCOL in [6, 17]:
            src_addr["Port"] = [ rec.SRC_PORT ]
        setAddr(src_addr, rec.SRC_IP)
    if rec.DST_IP:
        dst_addr = {
            "Proto": [ protocol ],
        }
        if rec.PROTOCOL != 1:
            dst_addr["Port"] = [ rec.DST_PORT ]
        setAddr(dst_addr, rec.DST_IP)

    for bit in bl_conv:

        if bit & blacklist:
            cur_bl = bl_conv[bit]
        else:
            # this bit is not a blacklist
            continue

        cur_bl_name = cur_bl["name"].lower()

        if (rec.EVENT_SCALE < int(bl_scale_tholds.get(cur_bl_name, 1))):
            # alert is not significant enough to put it into alert
            continue

        tor = False
        if cur_bl_name == "tor":
            tor = True
            category.add( "Suspicious.TOR" )
            if rec.SRC_IP and bit & rec.SRC_BLACKLIST:
                src_type.add("TOR")
                src_entries.add("TOR exit node")
            else:
                pass # don't set Type for address contacting TOR exit node
            if rec.DST_IP and bit & rec.DST_BLACKLIST:
                dst_type.add("TOR")
                dst_entries.add("TOR exit node")
            else:
                pass # don't set Type for address contacted by TOR exit node
            sources.add(cur_bl["source"])
        elif cur_bl["type"] == "BOTNET":
            category.add( "Intrusion.Botnet" )
            src_type.add("Botnet")
            dst_type.add("Botnet")
            if bit & rec.DST_BLACKLIST:
                dst_type.add("CC")
            if bit & rec.SRC_BLACKLIST:
                src_type.add("CC")
        elif cur_bl["type"] == "SPAM":
            category.add( "Abusive.Spam" )
        elif cur_bl["type"] == "Ransomware":
            category.add( "Malware.Ransomware" )

        if rec.SRC_IP and bit & rec.SRC_BLACKLIST and not tor:
            src_entries.add(cur_bl["name"])
        if rec.DST_IP and bit & rec.DST_BLACKLIST and not tor:
            dst_entries.add(cur_bl["name"])
        sources.add(cur_bl["source"])
    if not category:
        # No threshold reached
        return None
    idea["Category"] = list(category)
    note = ""
    if src_entries:
        note = 'Source IP {0} was found on blacklist(s): {1}.'.format(rec.SRC_IP, ", ".join(list(src_entries)))
    if dst_entries:
        if note:
            note = note + " "
        note = 'Destination IP {0} was found on blacklist(s): {1}.'.format(rec.DST_IP, ", ".join(list(dst_entries)))
    if note:
        idea["Note"] = note

    if src_addr:
        src_addr["Type"] = list(src_type)
        idea['Source'].append(src_addr)
    if dst_addr:
        dst_addr["Type"] = list(dst_type)
        idea['Source'].append(dst_addr)

    if src_entries:
        descSRC = "{0} (listed: {1})".format(rec.SRC_IP, ", ".join(list(src_entries)))
    else:
        descSRC = "{0}".format(rec.SRC_IP)

    if dst_entries:
        descDST = "{0} (listed: {1})".format(rec.DST_IP, ", ".join(list(dst_entries)))
    else:
        descDST = "{0}".format(rec.DST_IP)

    idea['Description'] = "{0} connected to {1}.".format(descSRC, descDST)
    if sources:
        idea['Ref'] = list(sources)
    return idea


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
parser = argparse.ArgumentParser()
parser.add_argument('--blacklist-config', help="Set path to bld_userConfigFile.xml of ipblacklistfilter. Default: /etc/nemea/ipblacklistfilter/bld_userConfigFile.xml", default="/etc/nemea/ipblacklistfilter/bld_userConfigFile.xml")

# Run the module
if __name__ == "__main__":
    Run(
        module_name = MODULE_NAME,
        module_desc = MODULE_DESC,
        req_type = REQ_TYPE,
        req_format = REQ_FORMAT,
        conv_func = convert_to_idea,
        arg_parser = parser
    )

