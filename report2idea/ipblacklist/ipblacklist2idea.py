#!/usr/bin/env python

import argparse

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "ipblacklist2idea"
MODULE_DESC = "Converts output of ipblacklistfilter module to IDEA."

REQ_TYPE = pytrap.FMT_JSON
REQ_FORMAT = "aggregated_ipblacklist"

# Blacklist ID to name lookup table (it is loaded from file specified by --blacklist-config in __main__)
bl_conv = {}

proto_conv = {
    1 : 'icmp',
    6 : 'tcp',
    17 : 'udp',
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
    rootElement = tree.find(".//array[@type='IP']")
    blacklists = list(rootElement)

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
                bl_id = 2 ** (int(el.text) - 1)
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
          Expected format is FMT_JSON and ipblacklist specifier.
          The example input data are as follows:
              {
                "src_sent_bytes": 0,
                "protocol": 6,
                "source_ports": [],
                "ts_last": 1533728805.882,
                "tgt_sent_packets": 9,
                "src_sent_flows": 0,
                "targets": [
                  "35.186.199.62"
                ],
                "sources": [
                  "93.171.202.150"
                ],
                "tgt_sent_flows": 1,
                "ts_first": 1533728776.706,
                "blacklist_bmp": 16,
                "tgt_sent_bytes": 964,
                "src_sent_packets": 0
              }

              {
                "src_sent_bytes": 1363,
                "protocol": 6,
                "source_ports": [],
                "ts_last": 1533728807.499,
                "ipb_bl": 3,
                "tgt_sent_packets": 6,
                "src_sent_flows": 1,
                "targets": [],
                "sources": [
                  "148.32.5.111",
                  "99.15.32.108"
                ],
                "tgt_sent_flows": 1,
                "ts_first": 1533728802.075,
                "ipa_bl": 1,
                "tgt_sent_bytes": 1363,
                "src_sent_packets": 6
              }

              {
                "src_sent_bytes": 6815,
                "protocol": 6,
                "source_ports": [],
                "ts_last": 1533728807.499,
                "tgt_sent_packets": 0,
                "src_sent_flows": 5,
                "targets": [
                  "150.32.5.111",
                  "149.32.5.111",
                  "152.32.5.111",
                  "153.32.5.111",
                  "151.32.5.111"
                ],
                "sources": [
                  "100.15.32.108"
                ],
                "tgt_sent_flows": 0,
                "ts_first": 1533728802.075,
                "blacklist_bmp": 1,
                "tgt_sent_bytes": 0,
                "src_sent_packets": 30
              }

    opts - options parsed from command line (as returned by argparse.ArgumentParser)

    Return report in IDEA format (as Python dict). If None is returned, the alert is skipped.
    """
    global bl_conv
    #import pdb
    #pdb.set_trace()

    if not bl_conv:
        bl_conv = load_config(opts.blacklist_config)

    protocol = ""
    if rec["protocol"] in proto_conv:
        protocol = proto_conv[rec["protocol"]]
    time_first = getIDEAtime(pytrap.UnirecTime(rec["ts_first"]))
    time_last = getIDEAtime(pytrap.UnirecTime(rec["ts_last"]))
    idea = {
        "Format": "IDEA0",
        "ID": getRandomId(),
        "CreateTime": getIDEAtime(), # Set current time
        "EventTime": time_first,
        "DetectTime": time_last,
        'CeaseTime': time_last,
        "FlowCount": rec["src_sent_flows"] + rec["tgt_sent_flows"],
        "PacketCount": rec["src_sent_packets"] + rec["tgt_sent_packets"],
        "ByteCount": rec["src_sent_bytes"] + rec["tgt_sent_bytes"],

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
    src_addr = { "Proto": [ protocol ] }
    src_entries = set()
    src_bl_map = dict()
    src_type = set()
    tgt_addr = { "Proto": [ protocol ] }
    tgt_type = set()
    sources = set()

    ips = [pytrap.UnirecIPAddr(ip) for ip in rec.get("sources", [])]

    for ip in rec.get("targets", []):
        setAddr(tgt_addr, pytrap.UnirecIPAddr(ip))

    if rec["protocol"] in [6, 17] and rec["source_ports"]:
        src_addr["Port"] = rec["source_ports"]

    botnet = False
    blacklist_bmp = rec.get("blacklist_bmp", 0)
    ipa_bl = rec.get("ipa_bl", 0)
    ipb_bl = rec.get("ipb_bl", 0)
    message_bl_sum = (blacklist_bmp | ipa_bl | ipb_bl)
    if blacklist_bmp:
        oneway = True
    else:
        oneway = False
        ips = [pytrap.UnirecIPAddr(i) for i in rec.get("sources", [])]
        ipa = min(ips)
        ipb = max(ips)

    for bit in bl_conv:

        if bit & message_bl_sum:
            cur_bl = bl_conv[bit]
        else:
            # this bit is not a blacklist
            continue

        cur_bl_name = cur_bl["name"].lower()

        tor = False
        curbltype = cur_bl["type"].lower()
        if curbltype == "tor":
            tor = True
            category.add( "Suspicious.TOR" )
            src_type.add("TOR")
            src_entries.add("TOR exit node")
            sources.add(cur_bl["source"])
        elif curbltype == "botnet":
            category.add( "Intrusion.Botnet" )
            src_type.add("Botnet")
            src_type.add("CC")
            tgt_type.add("Botnet")
            botnet = True
        elif curbltype == "spam":
            category.add( "Abusive.Spam" )
        elif curbltype == "ransomware":
            category.add( "Malware.Ransomware" )

        if not tor:
            src_entries.add(cur_bl["name"])
        if not oneway:
            if bit & ipa_bl:
                if str(ipa) not in src_bl_map:
                    src_bl_map[str(ipa)] = set()
                src_bl_map[str(ipa)].add(cur_bl["name"])
            if bit & ipb_bl:
                if str(ipb) not in src_bl_map:
                    src_bl_map[str(ipb)] = set()
                src_bl_map[str(ipb)].add(cur_bl["name"])
        sources.add(cur_bl["source"])

    for ip in ips:
        setAddr(src_addr, ip)

    if not category:
        # No threshold reached
        return None
    idea["Category"] = list(category)
    note = ""
    if src_entries and oneway:

        idea["Note"] = 'IP {0} was found on blacklist(s): {1}.'.format(", ".join(rec["sources"]), ", ".join(list(src_entries)))

        descsrc = "{0} (listed: {1})".format(", ".join(rec["sources"]), ", ".join(list(src_entries)))
    elif not oneway:
        descsrc = ", ".join(["{0} (listed: {1})".format(i, ", ".join(src_bl_map[i])) for i in src_bl_map])
    else:
        descsrc = "{0}".format(", ".join(rec["sources"]))

    if rec.get("targets", []):
        desctgt = "{0}".format(", ".join(rec["targets"]))
        idea['Description'] = "{0} communicated with {1}.".format(descsrc, desctgt)
    else:
        idea['Description'] = "Observed communication of {0}.".format(descsrc)

    if src_type:
        src_addr["Type"] = list(src_type)
    if tgt_type:
        tgt_addr["Type"] = list(tgt_type)
    if botnet:
        if rec.get("targets", []):
            idea['Source'].append(tgt_addr)
    else:
        if rec.get("targets", []):
            idea['Target'] = []
            idea['Target'].append(tgt_addr)
        if rec["src_sent_flows"]:
            src_addr["OutFlowCount"] = rec["src_sent_flows"]
            src_addr["OutByteCount"] = rec["src_sent_bytes"]
            src_addr["OutPacketsCount"] = rec["src_sent_packets"]
        if rec["tgt_sent_flows"]:
            src_addr["InFlowCount"] = rec["tgt_sent_flows"]
            src_addr["InByteCount"] = rec["tgt_sent_bytes"]
            src_addr["InPacketsCount"] = rec["tgt_sent_packets"]
    idea['Source'].append(src_addr)

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

