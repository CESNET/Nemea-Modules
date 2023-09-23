#!/usr/bin/env python

import argparse
import pytrap
import statistics
import json
from itertools import groupby

def all_equal(iterable):
    g = groupby(iterable)
    return next(g, True) and not next(g, False)

def gen_agg_func(oper, step = 1, start = 0):
    def agg_func(a, b):
        if isinstance(a, list):
            res = []
            opItems = [i for i in range(start, len(a), step)]
            for i,(ae,be) in enumerate(zip(a, b)):
                if(not i in opItems):
                    res.append(ae)
                else:
                    res.append(oper([ae, be]))
            return res
        else:
            return oper([a, b])
    return agg_func

agg_func_map = {
    "AVG": lambda args : gen_agg_func(statistics.mean),
    "SUM": lambda args : gen_agg_func(sum),
    "SUM_ARR": lambda args : gen_agg_func(sum),
    "RATE": lambda args : gen_agg_func(sum),
    "COUNT_UNIQ": lambda args : gen_agg_func(sum, 2, 1) if len(args) > 1 else gen_agg_func(sum),
    "COUNT": lambda args : gen_agg_func(sum),
    "HIST": lambda args : gen_agg_func(sum)
}

tmpl_map = {
    "AVG": lambda args : "double",
    "SUM": lambda args : "double",
    "SUM_ARR": lambda args : "double*",
    "RATE": lambda args : "double",
    "COUNT_UNIQ": lambda args : "uint64*" if len(args) > 1 else "uint64",
    "COUNT": lambda args : "uint64",
    "HIST": lambda args : "uint64*"
}

def parse_rule(rule : str):
    parts = rule.split(":")
    name = parts[0].strip()
    functionStr = parts[1].strip()
    functionName, functionArgs,*rest = functionStr.split("(")
    functionArgsArr = list(map(str.strip, functionArgs.split(",")))
    functionArgsArr[-1] = functionArgsArr[-1].rstrip(")")
    templateName = functionArgsArr[0]

    r = {
        "name": name,
        "function": functionName.strip(),
        "arguments": functionArgsArr,
        "template": tmpl_map[functionName](functionArgsArr)
    }
    return r

def merge_records(outRec, rules, records):
    # outRec = dict()
    setattr(outRec, "TIME", records[0].TIME)

    for rule in rules:
        merge_list = []
        for rec in records:
            val = getattr(rec, rule["name"])
            merge_list.append(val)

        outValue = merge_list[0]
        merge_list.pop(0)
        agg_func = agg_func_map[rule["function"]](rule["arguments"])
        while len(merge_list) != 0:
            outValue = agg_func(outValue, merge_list[0])
            merge_list.pop(0)
        setattr(outRec, rule["name"], outValue)
        
    return outRec

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ifcspec')
parser.add_argument('-n', '--aggnumber', type=int)
parser.add_argument('-r', '--rules', action='append', nargs='+')
args = parser.parse_args()

# Initialize module
ctx = pytrap.TrapCtx()
ctx.init(["-i", args.ifcspec], ifcin=args.aggnumber, ifcout=1)
for i in range(0, args.aggnumber):
    ctx.setRequiredFmt(i, pytrap.FMT_UNIREC, "time TIME")


rules = list(map(parse_rule, map(lambda x: x[0], args.rules)))
tmplFields = ["time TIME"]
tmplFields += map(lambda x: "{} {}".format(x['template'], x['name']), rules)
outFmt = ",".join(tmplFields)
ctx.setDataFmt(0, pytrap.FMT_UNIREC, outFmt)

recDatas = [None for i in range(0, args.aggnumber)]
recFmt = [None for i in range(0, args.aggnumber)]
recTmpls = [None for i in range(0, args.aggnumber)]
outTmpl = None


def recReady(recDatas):
    if None in recDatas:
        return False
    return all_equal(map(lambda x: x.TIME, recDatas))

def recNReadyIndex(data):
    try:
        return data.index(None)
    except ValueError:
        times = list(map(lambda x: x.TIME, data))
        if all_equal(map(lambda x: x.TIME, data)):
            raise ValueError()
        return times.index(min(times))

running = True
while running:
    curTmpls = [None for i in range(0, args.aggnumber)]
    try:
        while running:
            i = recNReadyIndex(curTmpls)
            try:
                recDatas[i] = ctx.recv(ifcidx=i)
            except pytrap.FormatChanged as e:
                recFmt[i] = ctx.getDataFmt(i)[1]
                recTmpls[i] = pytrap.UnirecTemplate(recFmt[i])
                recDatas[i] = e.data
                outTmpl = pytrap.UnirecTemplate(outFmt)
                del(e)
            if(len(recDatas[i]) == 0): 
                running = False
                break
            recTmpls[i].setData(recDatas[i])
            curTmpls[i] = recTmpls[i]
    except ValueError:
        pass
    if running == False:
        break

    #Join records
    outTmpl.createMessage(dyn_size=curTmpls[0].recVarlenSize())
    merge_records(outTmpl, rules, curTmpls)
    # print(outTmpl.strRecord(), outTmpl.recSize(), len(outTmpl.getData()))
    ctx.send(ifcidx=0, data=outTmpl.getData())
    ctx.sendFlush(0)
ctx.finalize()
