#!/usr/bin/python3

"""
Test unirecfilter by generating test data, filtering them, and checking the result.
"""

import subprocess
import os
import unittest
import pytrap

INPUTTESTFILENAME="/tmp/input.trapcap"
OUTPUTTESTFILENAME="/tmp/output.trapcap"

class PytrapHelper():
    """
    Helper to init, use and finalize pytrap.
    """
    def prepare_data_start(self):
        """Start storing the test records into INPUTTESTFILENAME - initialization."""
        fmttype = pytrap.FMT_UNIREC
        fmtspec = "ipaddr SRC_IP,ipaddr DST_IP,uint16 SRC_PORT,uint16 DST_PORT,uint64 BYTES"
        self.rec = pytrap.UnirecTemplate(fmtspec)
        self.rec.createMessage(0)

        self.trap = pytrap.TrapCtx()
        self.trap.init(["-i", f"f:{INPUTTESTFILENAME}:w"], 0, 1)
        self.trap.setDataFmt(0, fmttype, fmtspec)
        return self.rec

    def store_test_record(self):
        """Store one UniRec record that was filled outside."""
        if self.trap:
            self.trap.send(self.rec.getData())

    def prepare_data_stop(self):
        """Finish storing test data."""
        self.trap.finalize()

    def eval_data_start(self):
        """Start evaluation of the stored data - initialization."""
        self.trap = pytrap.TrapCtx()
        self.trap.init(["-i", f"f:{OUTPUTTESTFILENAME}"], 1, 0)
        self.trap.setRequiredFmt(0, pytrap.FMT_UNIREC)

    def load_result_record(self):
        """Load one UniRec record for evaluation, return None when no more data."""
        try:
            data = self.trap.recv()
        except pytrap.FormatChanged as err:
            fmttype, fmtspec = self.trap.getDataFmt(0)
            self.rec = pytrap.UnirecTemplate(fmtspec)
            data = err.data
        if len(data) <= 1:
            # empty message - do not process it!!!
            return None

        self.rec.setData(data)
        return self.rec

    def eval_data_stop(self):
        """Finish evaluation."""
        self.trap.finalize()

    def run_unirecfilter(self, urfilter):
        ans = subprocess.check_output(["../unirecfilter", "-i",
                                       f"f:{INPUTTESTFILENAME},f:{OUTPUTTESTFILENAME}", "-F", urfilter])
        ans = ans.decode("utf-8")
        return ans

class IPPrefixTest(unittest.TestCase):
    """Test case to check IP prefix in filters"""

    def setUp(self):
        self.trap = PytrapHelper()

    def tearDown(self):
        os.unlink(INPUTTESTFILENAME)
        os.unlink(OUTPUTTESTFILENAME)

    def test_eq(self):
        f = "SRC_IP == 192.168.0.0/16"

        # generate test data
        falseip = ("10.0.0.1", "172.0.0.1", "192.99.0.1")
        trueip = ("192.168.0.0", "192.168.0.1", "192.168.0.255", "192.168.255.255")
        rec = self.trap.prepare_data_start()
        for ip in falseip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()

        for ip in trueip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        while rec:
            self.assertIn(str(rec.SRC_IP), trueip)
            self.assertNotIn(str(rec.SRC_IP), falseip)
            rec = self.trap.load_result_record()

        self.trap.eval_data_stop()

    def test_in(self):
        f = "SRC_IP in [192.168.0.0/16, 10.0.0.0/24, fe80::/8, fd00:ff00::/16]"

        # generate test data
        falseip = ("172.0.0.1", "192.99.0.1", "1001:ffff::abcd")
        trueip = ("10.0.0.1", "192.168.0.0", "192.168.0.1", "192.168.0.255", "192.168.255.255", "fe80:12:0:34::56")
        rec = self.trap.prepare_data_start()
        for ip in falseip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()

        for ip in trueip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        while rec:
            self.assertIn(str(rec.SRC_IP), trueip)
            self.assertNotIn(str(rec.SRC_IP), falseip)
            rec = self.trap.load_result_record()

        self.trap.eval_data_stop()

    def test_host(self):
        f = "host in [192.168.0.0/16, 10.0.0.0/24, 2001:1234:dead:beef::/64]"

        # generate test data
        falseip = ("0.0.0.0", "172.0.0.1", "172.16.0.2", "192.99.0.1", "fe80:1234::1", "2001:4321::10")
        trueip = ("10.0.0.1", "192.168.0.0", "192.168.0.1", "192.168.0.255", "192.168.255.255", "2001:1234:dead:beef:cafe::1")
        rec = self.trap.prepare_data_start()
        recno = 0
        for ip1 in falseip:
            for ip2 in trueip:
                rec.SRC_IP = pytrap.UnirecIPAddr(ip1)
                rec.DST_IP = pytrap.UnirecIPAddr(ip2)
                self.trap.store_test_record()
                recno +=1

        for ip1 in trueip:
            for ip2 in falseip:
                rec.SRC_IP = pytrap.UnirecIPAddr(ip1)
                rec.DST_IP = pytrap.UnirecIPAddr(ip2)
                self.trap.store_test_record()
                recno +=1

        for ip1 in trueip:
            for ip2 in trueip:
                rec.SRC_IP = pytrap.UnirecIPAddr(ip1)
                rec.DST_IP = pytrap.UnirecIPAddr(ip2)
                self.trap.store_test_record()
                recno +=1

        lasttrue = recno

        for ip1 in falseip:
            for ip2 in falseip:
                rec.SRC_IP = pytrap.UnirecIPAddr(ip1)
                rec.DST_IP = pytrap.UnirecIPAddr(ip2)
                self.trap.store_test_record()
                recno +=1

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        recno = 0
        while rec:
            srcip = str(rec.SRC_IP)
            dstip = str(rec.DST_IP)
            src = srcip in trueip
            dst = dstip in trueip

            self.assertTrue(src or dst, f"Record number {recno} (<= {lasttrue}), the filter should be True for SRC or DST. {srcip}-{dstip}, {src}-{dst}")
            self.assertTrue(recno <= lasttrue)
                
            rec = self.trap.load_result_record()
            recno += 1

        self.trap.eval_data_stop()

    def test_host_eq(self):
        f = "host == 192.168.0.0/16"

        # generate test data
        falseip = ("0.0.0.0", "172.0.0.1", "172.16.0.2", "192.99.0.1", "fe80:1234::1", "10.0.0.1", "2001:1234:dead:beef:cafe::1", "2001:4321::10")
        trueip = ("192.168.0.0", "192.168.0.1", "192.168.0.255", "192.168.255.255")
        rec = self.trap.prepare_data_start()
        recno = 0
        for ip1 in falseip:
            for ip2 in trueip:
                rec.SRC_IP = pytrap.UnirecIPAddr(ip1)
                rec.DST_IP = pytrap.UnirecIPAddr(ip2)
                self.trap.store_test_record()
                recno +=1

        for ip1 in trueip:
            for ip2 in falseip:
                rec.SRC_IP = pytrap.UnirecIPAddr(ip1)
                rec.DST_IP = pytrap.UnirecIPAddr(ip2)
                self.trap.store_test_record()
                recno +=1

        for ip1 in trueip:
            for ip2 in trueip:
                rec.SRC_IP = pytrap.UnirecIPAddr(ip1)
                rec.DST_IP = pytrap.UnirecIPAddr(ip2)
                self.trap.store_test_record()
                recno +=1

        lasttrue = recno

        for ip1 in falseip:
            for ip2 in falseip:
                rec.SRC_IP = pytrap.UnirecIPAddr(ip1)
                rec.DST_IP = pytrap.UnirecIPAddr(ip2)
                self.trap.store_test_record()
                recno +=1

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        recno = 0
        while rec:
            srcip = str(rec.SRC_IP)
            dstip = str(rec.DST_IP)
            src = srcip in trueip
            dst = dstip in trueip

            self.assertTrue(src or dst, f"Record number {recno} (<= {lasttrue}), the filter should be True for SRC or DST. {srcip}-{dstip}, {src}-{dst}")
            self.assertTrue(recno <= lasttrue)
                
            rec = self.trap.load_result_record()
            recno += 1

        self.trap.eval_data_stop()


class PortTest(unittest.TestCase):
    """Test case to check IP prefix in filters"""

    def setUp(self):
        self.trap = PytrapHelper()

    def tearDown(self):
        os.unlink(INPUTTESTFILENAME)
        os.unlink(OUTPUTTESTFILENAME)

    def test_eq(self):
        f = "SRC_PORT == 123"

        # generate test data
        falsedata = (1, 10, 1000, 1234, 10123)
        truedata = [123]
        rec = self.trap.prepare_data_start()
        for el in falsedata:
            rec.SRC_PORT = el
            self.trap.store_test_record()

        for el in truedata:
            rec.SRC_PORT = el
            self.trap.store_test_record()

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        while rec:
            self.assertIn(rec.SRC_PORT, truedata)
            self.assertNotIn(rec.SRC_PORT, falsedata)
            rec = self.trap.load_result_record()

        self.trap.eval_data_stop()

    def test_in(self):
        f = "SRC_PORT in [11, 22, 123, 50000]"

        # generate test data
        falsedata = (1, 10, 1000, 1234, 10123)
        truedata = (123, 8080, 50000)

        rec = self.trap.prepare_data_start()
        for el in falsedata:
            rec.SRC_PORT = el
            self.trap.store_test_record()

        for el in truedata:
            rec.SRC_PORT = el
            self.trap.store_test_record()

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        while rec:
            self.assertIn(rec.SRC_PORT, truedata)
            self.assertNotIn(rec.SRC_PORT, falsedata)
            rec = self.trap.load_result_record()

        self.trap.eval_data_stop()

    def test_port(self):
        f = "port in [21, 22, 23, 80, 443]"

        # generate test data
        falsedata = (1, 10, 444, 65000)
        truedata = (22, 80, 443)
        rec = self.trap.prepare_data_start()
        recno = 0
        for el1 in falsedata:
            for el2 in truedata:
                rec.SRC_PORT = el1
                rec.DST_PORT = el2
                self.trap.store_test_record()
                recno +=1

        for el1 in truedata:
            for el2 in falsedata:
                rec.SRC_PORT = el1
                rec.DST_PORT = el2
                self.trap.store_test_record()
                recno +=1

        for el1 in truedata:
            for el2 in truedata:
                rec.SRC_PORT = el1
                rec.DST_PORT = el2
                self.trap.store_test_record()
                recno +=1

        lasttrue = recno

        for el1 in falsedata:
            for el2 in falsedata:
                rec.SRC_PORT = el1
                rec.DST_PORT = el2
                self.trap.store_test_record()
                recno +=1

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        recno = 0
        while rec:
            srcel = rec.SRC_PORT
            dstel = rec.DST_PORT
            src = srcel in truedata
            dst = dstel in truedata

            self.assertTrue(src or dst, f"Record number {recno} (<= {lasttrue}), the filter should be True for SRC or DST. {srcel}-{dstel}, {src}-{dst}")
            self.assertTrue(recno <= lasttrue)
                
            rec = self.trap.load_result_record()
            recno += 1

        self.trap.eval_data_stop()


    def test_port_eq(self):
        f = "port == 80"

        # generate test data
        falsedata = (1, 10, 444, 65000)
        truedata = (22, 80, 443)
        rec = self.trap.prepare_data_start()
        recno = 0
        for el1 in falsedata:
            for el2 in truedata:
                rec.SRC_PORT = el1
                rec.DST_PORT = el2
                self.trap.store_test_record()
                recno +=1

        for el1 in truedata:
            for el2 in falsedata:
                rec.SRC_PORT = el1
                rec.DST_PORT = el2
                self.trap.store_test_record()
                recno +=1

        for el1 in truedata:
            for el2 in truedata:
                rec.SRC_PORT = el1
                rec.DST_PORT = el2
                self.trap.store_test_record()
                recno +=1

        lasttrue = recno

        for el1 in falsedata:
            for el2 in falsedata:
                rec.SRC_PORT = el1
                rec.DST_PORT = el2
                self.trap.store_test_record()
                recno +=1

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        recno = 0
        while rec:
            srcel = rec.SRC_PORT
            dstel = rec.DST_PORT
            src = srcel in truedata
            dst = dstel in truedata

            self.assertTrue(src or dst, f"Record number {recno} (<= {lasttrue}), the filter should be True for SRC or DST. {srcel}-{dstel}, {src}-{dst}")
            self.assertTrue(recno <= lasttrue)
                
            rec = self.trap.load_result_record()
            recno += 1

        self.trap.eval_data_stop()

class BooleanTest(unittest.TestCase):
    """Test case to check IP prefix in filters"""

    def setUp(self):
        self.trap = PytrapHelper()

    def tearDown(self):
        #os.unlink(INPUTTESTFILENAME)
        os.unlink(OUTPUTTESTFILENAME)

    def test_true(self):
        f = "true"

        # generate test data
        trueip = ("192.168.0.0", "192.168.0.1", "192.168.0.255", "192.168.255.255")
        rec = self.trap.prepare_data_start()
        for ip in trueip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        while rec:
            self.assertIn(str(rec.SRC_IP), trueip)
            rec = self.trap.load_result_record()

        self.trap.eval_data_stop()

    def test_false(self):
        f = "false"

        # generate test data
        trueip = ("192.168.0.0", "192.168.0.1", "192.168.0.255", "192.168.255.255")
        rec = self.trap.prepare_data_start()
        for ip in trueip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        rec = self.trap.load_result_record()
        while rec:
            self.assertNotIn(str(rec.SRC_IP), trueip)
            rec = self.trap.load_result_record()

        self.trap.eval_data_stop()

    def test_alwaysfalse(self):
        f = "SRC_IP in [192.168.0.0/24] and false"

        # generate test data
        trueip = ("192.168.0.0", "192.168.0.1")
        falseip = ("10.1.2.3", "192.168.255.255")
        rec = self.trap.prepare_data_start()
        for ip in trueip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()
        for ip in falseip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        mergedlist = trueip + falseip
        rec = self.trap.load_result_record()
        while rec:
            self.assertNotIn(str(rec.SRC_IP), mergedlist)
            rec = self.trap.load_result_record()

        self.trap.eval_data_stop()

    def test_alwaystrue(self):
        f = "SRC_IP in [192.168.0.0/24] or true"

        # generate test data
        trueip = ("192.168.0.0", "192.168.0.1")
        falseip = ("10.1.2.3", "192.168.255.255")
        rec = self.trap.prepare_data_start()
        for ip in trueip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()
        for ip in falseip:
            rec.SRC_IP = pytrap.UnirecIPAddr(ip)
            self.trap.store_test_record()

        self.trap.prepare_data_stop()

        self.trap.run_unirecfilter(f)

        self.trap.eval_data_start()
        mergedlist = trueip + falseip
        rec = self.trap.load_result_record()
        while rec:
            self.assertIn(str(rec.SRC_IP), mergedlist)
            rec = self.trap.load_result_record()

        self.trap.eval_data_stop()



if __name__ == '__main__':
    unittest.main()
