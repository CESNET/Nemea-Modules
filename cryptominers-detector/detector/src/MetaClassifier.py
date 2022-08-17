#################################################
# \file MetaClassifier.py                       #
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


import pickle
import os
import numpy as np
from hashlib import sha256
from src.TlsSniCryptoDetector import TlsSniCryptoDetector
from src.StratumDetector import StratumDetector
from src.FeatureGenerator import getFeatures
from src.DSTCombinator import DSTCombinator
from src.DebugMetrics import DebugMetrics


class MetaClassifier:
    """
    MetaClassifier class.
    Implementation of the Meta classifier.
    """

    FEATURE_NAMES = [
        'BYTES',
        'BYTES_REV',
        'PACKETS',
        'PACKETS_REV',
        'SENT_PERCENTAGE',
        'RECV_PERCENTAGE',
        'AVG_PKT_INTERVAL',
        'OVERALL_DURATION',
        'AVG_PKT_LEN',
        'PSH_RATIO',
        'MIN_PKT_LEN',
        'DATA_SYMMETRY'
    ]

    def __init__(self, modelPath: str, dstThreshold: float, mlThreshold: float, debug: bool, useDstCache: bool, dstPortFilter: bool):
        """
        Init.
        Parameters:
            modelPath: string, path to the trained ML model
            dstThreshold: threshold for the DST [0..1]
            mlThreshold: threshold for ML probability [0..1]
            debug: True if Meta classifier should run in the verification and evaluation mode
        """
        self.DST_THRESHOLD = dstThreshold
        self.ML_THRESHOLD = mlThreshold
        self.DEBUG = debug
        self.USE_DST_CACHE = useDstCache
        self.DST_PORT_PREFILTER_ACTIVE = dstPortFilter
        self.metrics = DebugMetrics(self.USE_DST_CACHE, [
            ['DST Threshold', dstThreshold],
            ['ML Threshold', mlThreshold],
            ['ML Model Path', modelPath],
            ['Use DST Cache', useDstCache],
            ['443 Filter', dstPortFilter]
        ])
        if not os.path.exists(modelPath):
            raise FileNotFoundError(f'ML Model on path `{modelPath}` not found!')

        self.stratumDetector = StratumDetector()
        self.tlsSniCryptoMatcher = TlsSniCryptoDetector(
            TlsSniCryptoDetector.getCryptoNames(),
            TlsSniCryptoDetector.getCryptoKeywords()
        )
        with open(modelPath, 'rb') as src:
            self.model = pickle.load(src)
        self.dstMiners = set()
        self.dstOthers = set()

    def detectMiners(self, flows):
        """
        Method for detection of miner flows.
        Parameters:
            flows: list of flows (buffer)
        Returns: list of miner flows
        """

        minerFlows = []
        nextProcessingIdxs = []

        # Firstly, try Stratum detection
        for i in range(len(flows)):
            if self.stratumDetector.doStratumDetection(flows[i].IDP_CONTENT, flows[i].IDP_CONTENT_REV):
                minerFlows.append((flows[i], 'S'))
                if self.DEBUG:
                    self.metrics.addResult('S', flows[i].LABEL, True)
            else:
                # If no Stratum was detected, add this flow to the follow-up detection
                nextProcessingIdxs.append(i)

        if len(nextProcessingIdxs) == 0:
            return minerFlows

        # At this point, we will definitely need features for ML
        featureFlows = []
        for idx in nextProcessingIdxs:
            flow = flows[idx]
            sent, recv, avgPktInterval, avgPktLen, pshRatio, minPktLen, dataSymmetry = getFeatures(
                flow.PPI_PKT_DIRECTIONS,
                flow.PPI_PKT_TIMES,
                flow.PPI_PKT_LENGTHS,
                flow.PPI_PKT_FLAGS
            )
            featureFlow = np.array([
                flow.BYTES,
                flow.BYTES_REV,
                flow.PACKETS,
                flow.PACKETS_REV,
                sent,
                recv,
                avgPktInterval,
                flow.TIME_LAST.getSeconds() - flow.TIME_FIRST.getSeconds(),
                avgPktLen,
                pshRatio,
                minPktLen,
                dataSymmetry
            ])
            featureFlows.append(featureFlow)

        # Prepare list with probabilities from ML
        mlMinerProbas = self.model.predict_proba(featureFlows)
        for localIdx, globalIdx in enumerate(nextProcessingIdxs):
            # If TLS SNI is present, do DST
            if len(flows[globalIdx].TLS_SNI) > 0:
                tlsSniScore = self.tlsSniCryptoMatcher.doFlowSniDetection(flows[globalIdx].TLS_SNI)
                dst = DSTCombinator.combine(mlMinerProbas[localIdx][1], tlsSniScore)
                prediction = dst > self.DST_THRESHOLD
                path = 'D'
                if self.USE_DST_CACHE:
                    self.updateDSTCache(flows[globalIdx], prediction)
            # Otherwise do ML only
            else:
                if self.USE_DST_CACHE:
                    flowKey = self.getFlowKey(flows[globalIdx])
                    if flowKey in self.dstMiners:
                        prediction = True
                        path = 'C'
                    elif flowKey in self.dstOthers:
                        prediction = False
                        path = 'C'
                    else:
                        # Do not do detection of flow which encrytped on 443 and do not have TLS SNI, since flow representing same connection
                        # was most probably processed before, and this only produces false positives
                        if self.DST_PORT_PREFILTER_ACTIVE and flows[globalIdx].DST_PORT == 443:
                            continue
                        prediction = mlMinerProbas[localIdx][1] > self.ML_THRESHOLD
                        path = 'M'
                else:
                    # Do not do detection of flow which encrytped on 443 and do not have TLS SNI, since flow representing same connection
                    # was most probably processed before, and this only produces false positives
                    if self.DST_PORT_PREFILTER_ACTIVE and flows[globalIdx].DST_PORT == 443:
                       continue
                    prediction = mlMinerProbas[localIdx][1] > self.ML_THRESHOLD
                    path = 'M'

            if prediction:
                minerFlows.append((flows[globalIdx], path))
            if self.DEBUG:
                self.metrics.addResult(path, flows[globalIdx].LABEL, prediction)

        return minerFlows

    def getMetrics(self):
        """
        Method for printing the results and detecion statistics.
        Available in the verification and evaluation mode only.
        """
        return self.metrics

    def updateDSTCache(self, flow, prediction):
        flowKey = self.getFlowKey(flow)
        if prediction:
            self.dstMiners.add(flowKey)
        else:
            self.dstOthers.add(flowKey)

    @staticmethod
    def getFlowKey(flow):
        strKey = ','.join([
            str(flow.SRC_IP),
            str(flow.DST_IP),
            str(flow.SRC_PORT),
            str(flow.DST_PORT),
            str(flow.PROTOCOL)
        ])
        return sha256(strKey.encode('utf-8')).hexdigest()


