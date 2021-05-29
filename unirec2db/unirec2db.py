#!/usr/bin/python3

import sys
import os.path
import pytrap
import json
import optparse
import datetime

import sqlalchemy as sa
from sqlalchemy import create_engine
from sqlalchemy.dialects import mysql
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy_utils as sau


def MakeDatetime(unirec_time):
    dt = unirec_time.toDatetime()
    fs = unirec_time.getTimeAsFloat()
    return dt + datetime.timedelta(microseconds=int((fs - int(fs))*1000000))

Base = declarative_base()

class BasicFlow(Base):
    __tablename__ = 'basic_flow'
    id=sa.Column(sa.Integer, primary_key=True)
    ip_src = sa.Column(sau.IPAddressType)
    ip_dst = sa.Column(sau.IPAddressType)
    port_src=sa.Column(sa.Integer)
    port_dst=sa.Column(sa.Integer)
    time_first = sa.Column(mysql.DATETIME(fsp=6)) 
    time_last = sa.Column(mysql.DATETIME(fsp=6)) 
    protocol=sa.Column(sa.SmallInteger)
    packets=sa.Column(sa.Integer)
    bytes=sa.Column(sa.BigInteger)

    def __init__(self, trap_rec):
        self.ip_src = trap_rec.SRC_IP
        self.ip_dst = trap_rec.DST_IP
        self.port_src = trap_rec.SRC_PORT
        self.port_dst = trap_rec.DST_PORT
        self.time_first = MakeDatetime(trap_rec.TIME_FIRST)
        self.time_last = MakeDatetime(trap_rec.TIME_LAST)
        self.protocol = trap_rec.PROTOCOL
        self.packets = trap_rec.PACKETS
        self.bytes = trap_rec.BYTES

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
      help="See https://nemea.liberouter.org/trap-ifcspec/", metavar="IFCSPEC")
parser.add_option("-d", dest="db",
    help="SQL Alchemy connection string")
parser.add_option("-v", "--verbose", action="store_true",
    help="Set verbose mode - print messages.")

# Parse remaining command-line arguments
(options, args) = parser.parse_args()

# Initialize database
#'mysql+pymysql://test:test@10.10.10.2/test'
#'postgresql://usr:pass@localhost:5432/sqlalchemy'
engine = create_engine(options.db)
# create a configured "Session" class
SessionMaker = sa.orm.sessionmaker(bind=engine)
# create a Session
sa_session = SessionMaker()

# generate database schema
Base.metadata.create_all(engine)

# Initialize module
trap = pytrap.TrapCtx()
trap.init(["-i", options.ifcspec])

# Set data type on input
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL,uint8 TCP_FLAGS")

stop = False
try:
    # Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
    while not stop:
        # Read data from input interface
        try:
            data = trap.recv()
        except pytrap.FormatMismatch:
            sys.stderr.write("Error: output and input interfaces data type or format mismatch\n")
            break
        except pytrap.FormatChanged as e:
            if options.verbose:
                print(trap.getDataFmt(0))

            recTmpl = pytrap.UnirecTemplate(trap.getDataFmt(0)[1])
            data = e.data
            pass
        except (pytrap.Terminated, KeyboardInterrupt):
            break
        # Check for "end-of-stream" record
        if len(data) <= 1:
            break

        recTmpl.setData(data)
        db_flow = BasicFlow(recTmpl);
        sa_session.add(db_flow)
        sa_session.commit()
finally:
    sa_session.close()

