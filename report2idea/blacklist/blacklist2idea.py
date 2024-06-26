#!/usr/bin/python3

import argparse
import sys
from datetime import timedelta
import xml.etree.ElementTree as xml

# The whole functionality of reporting is here:
from report2idea import *


# Moudle name, description and required input data format
MODULE_NAME = "blacklist"
MODULE_DESC = "Converts output of (ip,url,dns)blacklistfilter modules to IDEA."

REQ_TYPE = pytrap.FMT_JSON
REQ_FORMAT = "aggregated_blacklist"

proto_conv = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
}

bl_config = None

# ---------------------------------------------------------------------------------------
# ------------------ DEFINITIONS OF IDEA CATEGORIES AS CLASSES --------------------------
# ---------------------------------------------------------------------------------------


class IdeaTemplate(object):
    """
    Idea template class generating all common fields of an IDEA message
    """

    def __init__(self, rec, bl):
        self.rec = rec
        self.bl = bl
        self.protocol = ""

        if rec["protocol"] in proto_conv:
            self.protocol = proto_conv[rec["protocol"]]
            self.tgt_addr = {"Proto": [self.protocol]}
            self.src_addr = {"Proto": [self.protocol]}
        else:
            # Add protocol only if it's known
            self.tgt_addr = {}
            self.src_addr = {}

        self.idea = {
            "Category": [bl["category"]],
            "Format": "IDEA0",
            "ID": getRandomId(),
            "CreateTime": getIDEAtime(),
            "EventTime": getIDEAtime(pytrap.UnirecTime(rec["ts_first"])),
            "DetectTime": getIDEAtime(pytrap.UnirecTime(rec["ts_last"])),
            "CeaseTime": getIDEAtime(pytrap.UnirecTime(rec["ts_last"])),
            "Source": [],
            "Node": [{
                "Name": "undefined",
                "SW": ["Nemea", "blacklistfilter"],
                "AggrWin": minutes_to_aggr_win(int(rec["agg_win_minutes"])),
                "Type": ["Flow", "Blacklist"]
            }],

            "Ref": [bl["source"]]
        }

    def get_idea(self):
        return self.idea

    def set_common_ip_fields(self):
        self.idea["Description"] = "Suspicious communication with IP listed on {0} blacklist".format(self.bl["name"])

        self.idea["FlowCount"] = self.rec["src_sent_flows"] + self.rec["tgt_sent_flows"]
        self.idea["PacketCount"] = self.rec["src_sent_packets"] + self.rec["tgt_sent_packets"]
        self.idea["ByteCount"] = self.rec["src_sent_bytes"] + self.rec["tgt_sent_bytes"]

        setAddr(self.src_addr, pytrap.UnirecIPAddr(self.rec["source"]))

        for ip in self.rec["targets"]:
            setAddr(self.tgt_addr, pytrap.UnirecIPAddr(ip))

        if self.rec["protocol"] in [6, 17] and self.rec["source_ports"]:
            self.src_addr["Port"] = self.rec["source_ports"]

        self.idea["Source"].append(self.src_addr)

        if self.rec["src_sent_flows"]:
            self.src_addr["OutFlowCount"] = self.rec["src_sent_flows"]
            self.src_addr["OutByteCount"] = self.rec["src_sent_bytes"]
            self.src_addr["OutPacketCount"] = self.rec["src_sent_packets"]
        if self.rec["tgt_sent_flows"]:
            self.src_addr["InFlowCount"] = self.rec["tgt_sent_flows"]
            self.src_addr["InByteCount"] = self.rec["tgt_sent_bytes"]
            self.src_addr["InPacketCount"] = self.rec["tgt_sent_packets"]
            self.idea["Source"].append(self.tgt_addr)
        else:
            self.idea["Description"] = "Blacklisted IP tried to communicate with host (with no response)"
            self.idea["Target"] = [self.tgt_addr]


    def set_common_url_fields(self):

        dsc = "Suspicious communication with {0} listed on {1} blacklist"
        self.idea["Description"] = dsc.format("domain name" if self.rec["is_only_fqdn"] else "URL",
                                              self.bl["name"])

        setAddr(self.src_addr, pytrap.UnirecIPAddr(self.rec["source_ip"]))

        for ip in self.rec["targets"]:
            setAddr(self.tgt_addr, pytrap.UnirecIPAddr(ip))

        if self.rec["protocol"] in [6, 17] and self.rec["source_ports"]:
            self.src_addr["Port"] = self.rec["source_ports"]

        if self.rec["is_only_fqdn"]:
            self.src_addr["Hostname"] = [self.rec["source_url"]]
        else:
            self.src_addr["URL"] = [self.rec["source_url"]]

        self.src_addr["Type"] = ["OriginBlacklist"]
        self.idea["Source"].append(self.src_addr)

        if self.rec["tgt_sent_flows"]:
            self.src_addr["InFlowCount"] = self.rec["tgt_sent_flows"]
            self.src_addr["InByteCount"] = self.rec["tgt_sent_bytes"]
            self.src_addr["InPacketCount"] = self.rec["tgt_sent_packets"]
            self.idea["Source"].append(self.tgt_addr)
        else:
            self.idea["Description"] = "Blacklisted IP tried to communicate with host (with no response)"
            self.idea["Target"] = [self.tgt_addr]


class GeneralAlert(IdeaTemplate):
    """
    Class representing a general IDEA message of any blacklist category (including IP and URL alerts),
    specialized categories (e.g. Intrusion.Botnet) are supposed to inherit from this class and rewrite IDEA as needed
    """
    def __init__(self, rec, bl):
        super(GeneralAlert, self).__init__(rec, bl)
        if rec["type"] == "ip":
            self.set_common_ip_fields()
        else:
            self.set_common_url_fields()


class IntrusionBotnet(GeneralAlert):
    def __init__(self, rec, bl):
        super(IntrusionBotnet, self).__init__(rec, bl)

        self.src_addr["Type"] = ["CC", "Botnet"]
        if rec["tgt_sent_flows"]:
            self.tgt_addr["Type"] = ["Botnet"]


class SuspiciousMiner(GeneralAlert):
    def __init__(self, rec, bl):
        super(SuspiciousMiner, self).__init__(rec, bl)

        self.src_addr["Type"] = ["PoolServer"]
        if rec["tgt_sent_flows"]:
            self.tgt_addr["Type"] = ["Miner"]


class SuspiciousBooter(GeneralAlert):
    def __init__(self, rec, bl):
        super(SuspiciousBooter, self).__init__(rec, bl)

        self.src_addr["Type"] = ["Booter"]


class FraudPhishing(GeneralAlert):
    def __init__(self, rec, bl):
        super(FraudPhishing, self).__init__(rec, bl)

        self.src_addr["Type"] = ["Phishing"]


# ---------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------


def convert_to_idea(rec, opts=None):
    """
    Converts the aggregated (ip/url)blacklistfilter event(json) to the IDEA format.
    It dynamically matches the blacklist category to alert classes (e.g. Intrusion.Botnet instantiates the class
    IntrusionBotnet). If there is no specific match, GeneralAlert is created, it also dynamically distinguishes IP/URL
    alerts.

    Args:
        rec: the record from ip/url blacklistfilter
        opts: cmd options

    Returns:
        dict: idea
    """

    # Set blacklist type according to the detector who sent the alert
    if rec["type"] == "ip":
        bl_type = "ip"
    else:
        bl_type = "url_dns"

    global bl_config
    if not bl_config:
        bl_config = load_blacklists(opts.blacklist_config)

    # Fetch the corresponding blacklist
    current_bl = bl_config[bl_type].get(rec["blacklist_id"])
    if current_bl is None:
        print("Reported blacklist '{}/{}' not found in configuration, skipping alert.".format(bl_type, rec["blacklist_id"]))
        return None

    # Try to match category to class (e.g. Intrusion.Botnet -> IntrusionBotnet
    category_class = current_bl["category"].replace('.', '')
    module = __import__('__main__')
    try:
        category_class = getattr(module, category_class)
        category_instance = category_class(rec, current_bl)
    except AttributeError:
        category_instance = GeneralAlert(rec, current_bl)

    return category_instance.get_idea()


def load_blacklists(config):
    """
    Load `config` file of blacklistfilter module (bl_downloader_config.xml).
    This file contains a list of blacklists, their names and URLs.

    load_config() returns dictionary, where the key is id (= 2**ID from file) and
    value is a dictionary of "name", "type", "source" and other parameters.

    Args:
        config: config file

    Returns:
        dict: blacklists
    """

    bls = {}
    with open(config, "r") as f:
        tree = xml.parse(f)

    ip_root_element = tree.find(".//array[@type='IP']")
    url_dns_root_element = tree.find(".//array[@type='URL/DNS']")

    ip_blacklists = list(ip_root_element) if ip_root_element else list()
    url_dns_blacklists = list(url_dns_root_element) if url_dns_root_element else list()

    for blacklists in [ip_blacklists, url_dns_blacklists]:
        bl_type = 'ip' if blacklists is ip_blacklists else 'url_dns'
        bls[bl_type] = {}

        for struct in blacklists:
            elems = list(struct)
            bl_id = None
            bl_name = None
            bl_category = None
            bl_source = None
            for el in elems:
                attr = el.attrib["name"]
                if attr == "name":
                    bl_name = el.text
                elif attr == "id":
                    bl_id = 2 ** (int(el.text) - 1)
                elif attr == "category":
                    bl_category = el.text
                elif attr == "source":
                    bl_source = el.text
            if not bl_id or not bl_name or not bl_category or not bl_source:
                sys.stderr.write("Incomplete configuration. " + str((bl_id, bl_name, bl_category)))
                break

            bls[bl_type][bl_id] = {"name": bl_name, "category": bl_category, "source": bl_source}

    return bls


def minutes_to_aggr_win(minutes):
    """
    Converts minutes to IDEA AggrWin format (e.g. 00:05:00 or 536D10:20:30)

    Args:
        minutes (int): minutes to convert

    Returns:
        str: converted string
    """

    td = str(timedelta(minutes=minutes))
    if minutes < 600:
        return "0" + td
    if minutes < 1440:
        return td

    days, time = td.split(',')
    if minutes % 1440 < 600:
        time = "0" + time.strip()

    return days.split(' ')[0] + "D" + time.strip()


# If conversion functionality needs to be parametrized, an ArgumentParser can be passed to Run function.
# These parameters are then parsed from command line and passed as "opts" parameter of the conversion function.
parser = argparse.ArgumentParser()
parser.add_argument('--blacklist-config', help="Set path to config file of blacklist downloader. Default: /etc/nemea/blacklistfilter/bl_downloader_config.xml",
                    default="/etc/nemea/blacklistfilter/bl_downloader_config.xml")

# Run the module
if __name__ == "__main__":
    Run(
        module_name=MODULE_NAME,
        module_desc=MODULE_DESC,
        req_type=REQ_TYPE,
        req_format=REQ_FORMAT,
        conv_func=convert_to_idea,
        arg_parser=parser
    )
