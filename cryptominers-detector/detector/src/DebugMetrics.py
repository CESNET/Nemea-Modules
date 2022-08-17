#################################################
# \file DebugMetrics.py                         #
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


class DebugMetrics:
    """
    Debug Metrics class.
    Class for simple calculation and evaluation of the detector's accuracy.
    """

    def __init__(self, mlWithDstCache, settings):
        self.stats = {
            'S': self.getEmptyStatsDict(), # Stratum Path
            'D': self.getEmptyStatsDict(), # DST Path
            'M': self.getEmptyStatsDict(), # ML Path
            'C': self.getEmptyStatsDict(), # DST Cache used in ML
        }
        self.ML_WITH_DST_CACHE = mlWithDstCache
        self.settings = settings

    def addResult(self, path, label, prediction):
        """
        Method to register new prediction made by detector.
        Parameters:
            path: 'S', 'D' or 'M', reason why flow was marked as a miner
            label: 'Miner' or 'Other', true label of flow
            prediction: True if detector marked flow as a miner, otherwise False
        """
        if label == 'Miner' and prediction:
            self.stats[path]['TP'] += 1
        elif label == 'Miner' and not prediction:
            self.stats[path]['FN'] += 1
        elif label == 'Other' and prediction:
            self.stats[path]['FP'] += 1
        elif label == 'Other' and not prediction:
            self.stats[path]['TN'] += 1
        else:
            raise Error('Unknown possibility in DebugMetrics.addResult()')

    @staticmethod
    def accuracy(TP, FP, FN, TN):
        if TP + FP + FN + TN == 0:
            return 0
        return ((TP + TN) / (TP + FP + FN + TN)) * 100

    @staticmethod
    def precision(TP, FP):
        if TP + FP == 0:
            return 0
        return (TP / (TP + FP)) * 100

    @staticmethod
    def f(d):
        return f'{d:.04f}'

    @staticmethod
    def evaluatePath(name, TP, FP, FN, TN):
        TOTAL = TP + FP + FN + TN
        accuracy = DebugMetrics.accuracy(TP, FP, FN, TN)
        precision = DebugMetrics.precision(TP, FP)
        print(f'{name}')
        print(f' {{ TP = {TP} ; FP = {FP} ; FN = {FN} ; TN = {TN} }}')
        print(f' Total  = {TOTAL}')
        print(f' Accuracy  = {DebugMetrics.f(accuracy)} %')
        print(f' Precision = {DebugMetrics.f(precision)} %')

    @staticmethod
    def evaluatePathWithCache(name, cacheName, TP, FP, FN, TN, cTP, cFP, cFN, cTN):
        TOTAL_PATH = TP + FP + FN + TN
        TOTAL_CACHE = cTP + cFP + cFN + cTN
        TOTAL = TOTAL_PATH + TOTAL_CACHE
        accuracyPath = DebugMetrics.accuracy(TP, FP, FN, TN)
        precisionPath = DebugMetrics.precision(TP, FP)
        accuracyCache = DebugMetrics.accuracy(cTP, cFP, cFN, cTN)
        precisionCache = DebugMetrics.precision(cTP, cFP)
        accuracyTotal = DebugMetrics.accuracy(TP + cTP, FP + cFP, FN + cFN, TN + cTN)
        precisionTotal = DebugMetrics.precision(TP + cTP, FP + cFP)
        print(f'{name} with {cacheName}')
        print(f' {name:<5} {{ TP = {TP} ; FP = {FP} ; FN = {FN} ; TN = {TN} }}')
        print(f' Total  = {TOTAL_PATH}')
        print(f' Accuracy  = {DebugMetrics.f(accuracyPath)} %')
        print(f' Precision = {DebugMetrics.f(precisionPath)} %')
        print()
        print(f' {cacheName:<5}: {{ TP = {cTP} ; FP = {cFP} ; FN = {cFN} ; TN = {cTN} }}')
        print(f' Total  = {TOTAL_CACHE}')
        print(f' Accuracy  = {DebugMetrics.f(accuracyCache)} %')
        print(f' Precision = {DebugMetrics.f(precisionCache)} %')
        print()
        print(f' {"Together":<5} {{ TP = {TP + cTP} ; FP = {FP + cFP} ; FN = {FN + cFN} ; TN = {TN + cTN} }}')
        print(f' Total  = {TOTAL}')
        print(f' Accuracy  = {DebugMetrics.f(accuracyTotal)} %')
        print(f' Precision = {DebugMetrics.f(precisionTotal)} %')

    def printMetrics(self):
        """
        Method to print statistics of the registered predictions.
        """

        for e in self.settings:
            print(f"{e[0]:<20} => {e[1]}")
        print()

        self.evaluatePath(
            'Stratum',
            self.stats['S']['TP'],
            self.stats['S']['FP'],
            self.stats['S']['FN'],
            self.stats['S']['TN']
        )
        print()
        self.evaluatePath(
            'DST',
            self.stats['D']['TP'],
            self.stats['D']['FP'],
            self.stats['D']['FN'],
            self.stats['D']['TN']
        )
        print()
        if self.ML_WITH_DST_CACHE:
            self.evaluatePathWithCache(
                'ML',
                'DST Cache',
                self.stats['M']['TP'],
                self.stats['M']['FP'],
                self.stats['M']['FN'],
                self.stats['M']['TN'],
                self.stats['C']['TP'],
                self.stats['C']['FP'],
                self.stats['C']['FN'],
                self.stats['C']['TN']
            )
        else:
            self.evaluatePath(
                'ML',
                self.stats['M']['TP'],
                self.stats['M']['FP'],
                self.stats['M']['FN'],
                self.stats['M']['TN']
            )
        print()
        tp = self.stats['S']['TP'] + self.stats['M']['TP'] + self.stats['D']['TP']
        fp = self.stats['S']['FP'] + self.stats['M']['FP'] + self.stats['D']['FP']
        fn = self.stats['S']['FN'] + self.stats['M']['FN'] + self.stats['D']['FN']
        tn = self.stats['S']['TN'] + self.stats['M']['TN'] + self.stats['D']['TN']
        total = tp + fp + fn + tn

        print(f'TP: {tp}\t({(tp/total) * 100:.04} %)')
        print(f'FP: {fp}\t({(fp/total) * 100:.04} %)')
        print(f'FN: {fn}\t({(fn/total) * 100:.04} %)')
        print(f'TN: {tn}\t({(tn/total) * 100:.04} %)')
        print(f'Total flows processed: {total}')
        print()

        accuracy = self.accuracy(tp, fp, fn, tn)
        precision = self.precision(tp, fp)
        print(f'Accuracy  = {accuracy:.04f} %')
        print(f'Precision = {precision:.04f} %')

    @staticmethod
    def getEmptyStatsDict():
        """
        Static method - getter for the empty TP,FP,FN,TN dict.
        Returns: prepared dict
        """
        return {
            'TP': 0,
            'FP': 0,
            'FN': 0,
            'TN': 0
        }
