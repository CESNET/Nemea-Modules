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

    def __init__(self):
        self.stats = {
            'S': self.getEmptyStatsDict(),
            'D': self.getEmptyStatsDict(),
            'M': self.getEmptyStatsDict(),
        }

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

    def printMetrics(self):
        """
        Method to print statistics of the registered predictions.
        """

        print(f"Stratum: {self.stats['S']}")
        accStratum = (self.stats['S']['TP'] + self.stats['S']['TN']) / (self.stats['S']['TP'] + self.stats['S']['FP'] + self.stats['S']['FN'] + self.stats['S']['TN'])
        accStratum *= 100
        print(f"Accuracy = {accStratum:.04f} %\n")

        print(f"DST:\t{self.stats['D']}")
        accDst = (self.stats['D']['TP'] + self.stats['D']['TN']) / (self.stats['D']['TP'] + self.stats['D']['FP'] + self.stats['D']['FN'] + self.stats['D']['TN'])
        accDst *= 100
        print(f"Accuracy = {accDst:.04f} %\n")

        print(f"ML:\t{self.stats['M']}")
        accMl = (self.stats['M']['TP'] + self.stats['M']['TN']) / (self.stats['M']['TP'] + self.stats['M']['FP'] + self.stats['M']['FN'] + self.stats['M']['TN'])
        accMl *= 100
        print(f"Accuracy = {accMl:.04f} %\n")

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

        acc = (tp + tn) / (tp + fp + fn + tn)
        acc *= 100
        print(f'Accuracy = {acc:.04f} %')

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
