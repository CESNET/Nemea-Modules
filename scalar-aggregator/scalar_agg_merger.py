import argparse
import pytrap
import statistics
import json

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
    "RATE": lambda args : gen_agg_func(sum),
    "COUNT_UNIQ": lambda args : gen_agg_func(sum, 2, 1) if len(args) > 1 else gen_agg_func(sum),
    "COUNT": lambda args : gen_agg_func(sum),
    "HIST": lambda args : gen_agg_func(sum)
}

tmpl_map = {
    "AVG": lambda args : "double",
    "SUM": lambda args : "double",
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
    templateName = functionArgs.split(",")[0]

    r = {
        "name": name,
        "function": functionName.strip(),
        "arguments": functionArgs.split(","),
        "template": tmpl_map[functionName](functionArgs.split(",")[0])
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


        if rule["name"] == "cnt_dst_ports" or rule["name"] == "cnt_src_ports":
            print(rule["name"])
            print(merge_list)
        outValue = merge_list[0]
        merge_list.pop(0)
        agg_func = agg_func_map[rule["function"]](rule["arguments"])
        while len(merge_list) != 0:
            outValue = agg_func(outValue, merge_list[0])
            merge_list.pop(0)

        if rule["name"] == "cnt_dst_ports" or rule["name"] == "cnt_src_ports":
            print(f"Set: {rule['name']} - {outValue}")
        setattr(outRec, rule["name"], outValue)
        if rule["name"] == "cnt_dst_ports" or rule["name"] == "cnt_src_ports":
            print(f"Get: {rule['name']} - {getattr(outRec, rule['name'])}")
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
tmplFields += map(lambda x: f"{x['template']} {x['name']}", rules)
outFmt = ",".join(tmplFields)
ctx.setDataFmt(0, pytrap.FMT_UNIREC, outFmt)

recDatas = [None for i in range(0, args.aggnumber)]
recFmt = [None for i in range(0, args.aggnumber)]
recTmpls = [None for i in range(0, args.aggnumber)]
outTmpl = None

running = True
while running:
    recList = []
    for i in range(args.aggnumber):
        try:
            recDatas[i] = ctx.recv(ifcidx=i)
        except pytrap.FormatChanged as e:
            recFmt[i] = ctx.getDataFmt(i)[1]
            recTmpls[i] = pytrap.UnirecTemplate(recFmt[i])
            recDatas[i] = e.data
            outTmpl = pytrap.UnirecTemplate(recFmt[i])
            del(e)
        if(len(recDatas[i]) == 0): 
            running = False
            break
        recTmpls[i].setData(recDatas[i])
    if running == False:
        break

    #Join records
    outTmpl.createMessage(dyn_size=recTmpls[0].recVarlenSize())
    merge_records(outTmpl, rules, recTmpls)
    print(outTmpl.strRecord(), outTmpl.recSize(), len(outTmpl.getData()))
    ctx.send(ifcidx=0, data=outTmpl.getData())
ctx.finalize()