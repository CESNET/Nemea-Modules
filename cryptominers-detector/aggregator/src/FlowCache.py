
#################################################
# \file FlowCache.py                            #
# \author Richard Plny <plnyrich@fit.cvut.cz>   #
# \date 2022                                    #
#################################################


# BSD 3-Clause License
# 
# Copyright (c) 2022, CESNET
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from hashlib import sha256
from threading import Lock
from src.FlowRecord import FlowRecord


class FlowCache:
    """
    FlowCache class.
    """
    def __init__(self, activeTimeout, passiveTimeout):
        """
        Init.
        Parameters:
            activeTimeout: number of flows needed for exporting record from cache
            passiveTimeout: number of seconds of inactivity after which record is exported
        """
        self.cache = {}
        self.mutex = Lock()
        self.activeTimeout = activeTimeout
        self.passiveTimeout = passiveTimeout

    def update(self, flow):
        """
        Method for adding/updating records in cache.
        Parameters:
            flow: received (miner) flow
        """
        key = self.flowKey(flow)
        self.mutex.acquire()
        try:
            # If flow key is in cache, update it, otherwise add a new record
            if key in self.cache:
                self.cache[key].update(flow)
            else:
                self.cache[key] = FlowRecord(flow)
        finally:
            self.mutex.release()

    def toExport(self):
        """
        Method for exporting records from flow cache.
        Only flows which meet at least one condition (activeTimeout or passiveTimeout) are exported.
        Returns: list of exported flow records
        """
        self.mutex.acquire()
        flowRecordsToExport = []
        try:
            for k in self.cache.copy():
                if self.cache[k].ready(self.activeTimeout, self.passiveTimeout):
                    flowRecordsToExport.append(self.cache[k])
                    self.cache.pop(k)
        finally:
            self.mutex.release()
        return flowRecordsToExport

    def getAll(self):
        """
        Method to get all records currently in cache.
        Cache is cleared afterwards.
        Returns: list of records which were present in cache before clear
        """
        self.mutex.acquire()
        try:
            flowRecordsToExport = list(self.cache.values())
            self.cache = {}
        finally:
            self.mutex.release()
        return flowRecordsToExport

    @staticmethod
    def flowKey(flow):
        """
        Static method for calculation of flow key.
        Parameters:
            flow: flow for which key is calculated
        Returns: SHA256 string which is used as a key into the flow cache
        """
        strKey = ','.join([
            str(flow.SRC_IP),
            str(flow.DST_IP),
            str(flow.SRC_PORT),
            str(flow.DST_PORT),
            str(flow.PROTOCOL)
        ])
        return sha256(strKey.encode('utf-8')).hexdigest()
