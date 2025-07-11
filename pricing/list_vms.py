#! /usr/bin/env python3

"""Show AWS instance pricing with optional filtering.
"""

import argparse
import fnmatch
import gzip
import json
import os.path
import re
import sys
import tabulate

# CPU feature words to ignore
CPU_FEATURES_HIDE = ["AVX", "AVX2", "Turbo", "Intel", "AMD", "ENA", "Learning", "Boost"]

# human readable CPU names

XEONS = [
    None,
    "X1 SandyB",
    "X2 IvyB",
    "X3 HasW",
    "X4 BroadW",
    "X5 SkyL",
    "X6 KabyL",
    "X7 CascadeL",
    "X8 IceL",
    "X9 Sapphire",
]

EPYC_V1 = "E1 Naples"
EPYC_V2 = "E2 Rome"
EPYC_V3 = "E3 Milan"
EPYC_V4 = "E4 Genoa"

AWS_GRAVITON = "G1 ARMv8"
AWS_GRAVITON2 = "G2 ARMv82"
AWS_GRAVITON3 = "G3 ARMv84"

def xeon(n, tag):
    return XEONS[n]  # + " " + tag


### task filter
# c - Compute
# f - FPGA
# g - GPU
# l - Machine Learning
# m - Memory
# n - General (normal)
# s - Storage
# u - Micro
# v - Media (video)
TASK_CODES = {
    "Compute": "c",
    "FPGA": "f",
    "General": "n",
    "GPU": "g",
    "Machine": "l",
    "Media": "v",
    "Memory": "m",
    "Micro": "u",
    "Storage": "s",
}

# map technical name to readable name
CPU_CODES = {
    "AMD EPYC 7571": EPYC_V1,
    "AMD EPYC 7R32": EPYC_V2,
    "AMD EPYC 7R13 Processor": EPYC_V3,
    "AMD EPYC 9R14 Processor": EPYC_V4,
    "AWS Graviton Processor": AWS_GRAVITON,
    "AWS Graviton2 Processor": AWS_GRAVITON2,
    "AWS Graviton3 Processor": AWS_GRAVITON3,
    "High Frequency Intel Xeon E7-8880 v3 (Haswell)": xeon(3, "E7-8880"),
    "Intel Skylake E5 2686 v5 (2.5 GHz)": xeon(5, "E5-2686"),
    "Intel Skylake E5 2686 v5": xeon(5, "E5-2686"),
    "Intel Xeon E5-2650": xeon(1, "E5-2650"),
    "Intel Xeon E5-2666 v3 (Haswell)": xeon(3, "E5-2666"),
    "Intel Xeon E5-2670": xeon(1, "E5-2670"),
    "Intel Xeon E5-2670 (Sandy Bridge)": xeon(1, "E5-2670"),
    "Intel Xeon E5-2670 v2 (Ivy Bridge)": xeon(2, "E5-2670"),
    "Intel Xeon E5-2670 v2 (Ivy Bridge/Sandy Bridge)": xeon(2, "E5-2670"),
    "Intel Xeon E5-2676 v3 (Haswell)": xeon(3, "E5-2676"),
    "Intel Xeon E5-2676v3 (Haswell)": xeon(3, "E5-2676"),
    "Intel Xeon E5-2680 v2 (Ivy Bridge)": xeon(2, "E5-2680"),
    "Intel Xeon E5-2686 v4 (Broadwell)": xeon(4, "E5-2686"),
    "Intel Xeon Family": "Xeon Family",
    "Intel Xeon Platinum 8124M": xeon(5, "P-8124M"),
    "Intel Xeon Platinum 8151": xeon(5, "P-8151"),
    "Intel Xeon Platinum 8175": xeon(5, "P-8175"),
    "Intel Xeon Platinum 8175 (Skylake)": xeon(5, "P-8175"),
    "Intel Xeon Platinum 8252": xeon(7, "P-8252"),
    "Intel Xeon Platinum 8259 (Cascade Lake)": xeon(7, "P-8259"),
    "Intel Xeon Platinum 8259CL": xeon(7, "P-8259CL"),
    "Intel Xeon Platinum 8275L": xeon(7, "P-8275L"),
    "Intel Xeon Platinum 8275CL (Cascade Lake)": xeon(7, "P-8275CL"),
    "Intel Xeon Platinum 8280L (Cascade Lake)": xeon(7, "P-8280L"),
    "Intel Xeon Scalable (Skylake)": xeon(5, "P-8176M"),
    "Intel Xeon Scalable (Icelake)": xeon(8, "P-8375C"),
    "Intel Xeon 8375C (Ice Lake)": xeon(8, "P-8375C"),
    "Intel Xeon Scalable (Sapphire Rapids)": xeon(9, "P-8488C"),
    "Variable": "Variable",
}

# approx clock when missing
CLOCK_SPEED = {
    "AWS Graviton2 Processor": 2.5,
    "Intel Xeon E5-2670": 3.3,
    "Intel Xeon Family": 2.0,
    "Intel Xeon Platinum 8275CL (Cascade Lake)": 3.0,
    "Intel Xeon Scalable (Skylake)": 3.8,
    "Variable": 2.6,
}

CCY_RATE = {
    "USD": 1,
    "CNY": 6.96772,
}

# https://www.intel.com/content/www/us/en/developer/articles/technical/intel-vtune-amplifier-functionality-on-aws-instances.html
# https://github.com/aws/aws-graviton-getting-started/blob/main/perfrunbook/debug_hw_perf.md
# https://oavdeev.github.io/posts/vpmu_support_z1d/
HW_PMU = {}

def has_hw_pmu(name):
    if name not in HW_PMU:
        pfx, size = name.split(".", 1)
        if "6g" in pfx:
            HW_PMU[name] = size in ("16xlarge", "metal")
        elif "7g" in pfx:
            HW_PMU[name] = size in ("16xlarge", "metal")
        elif "6i" in pfx:
            HW_PMU[name] = size in ("16xlarge", "32xlarge", "metal")
        elif "5a" in pfx:
            HW_PMU[name] = False
        elif pfx[:2] in ("m5", "c5", "r5"):
            HW_PMU[name] = size in ("16xlarge", "24xlarge", "metal")
        else:
            HW_PMU[name] = False
    return HW_PMU[name]

# approx numbers for speed hints on old instances
# https://stackoverflow.com/questions/18507405/ec2-instance-typess-exact-network-performance/35806587
OLD_NET = {
    "Very Low": "~0.1",
    "Low": "~0.3",
    "Low to Moderate": "~0.4",
    "Moderate": "~0.5",
    "High": "~1",
}

RES_YEARS = {
    "1yr": 1,
    "3yr": 3,
}
RES_OPT = {
    "No Upfront": "none",
    "Partial Upfront": "part",
    "All Upfront": "upfront",
}

RES_ARG_MAP = {
    "1": "1yr",
    "3": "3yr",
    "n": "none",
    "p": "part",
    "a": "upfront",
    "s": "standard",
    "c": "convertible",
}

BWMULT = {'Mbps': 1.0/1000, 'Gbps': 1.0}

PRICE_KEY = "ondemand"


def roundFloat(f):
    return float("%.02f" % f)


def getPricePerUnit(pdim):
    ppu = pdim["pricePerUnit"]
    for code in CCY_RATE:
        if code in ppu:
            return float(ppu[code])
    raise ValueError("Unknown currency: %r" % list(ppu))


def getPriceMap(rec):
    """Return price as float.
    """
    ondemand = list(rec["terms"]["OnDemand"].values())
    reserved = list(rec["terms"].get("Reserved", {}).values())
    priceMap = {}
    for rtype in reserved:
        rlen = rtype["termAttributes"]["LeaseContractLength"]
        ropt = rtype["termAttributes"]["PurchaseOption"]
        rclass = rtype["termAttributes"]["OfferingClass"]
        rname = "reserved/%s/%s/%s" % (
            rlen,
            rclass,
            RES_OPT[ropt],
        )
        nyear = RES_YEARS[rlen]
        price = 0
        for pdim in rtype["priceDimensions"].values():
            if pdim.get("beginRange", "0") != "0":
                raise ValueError("unexpected beginRange: %r" % (pdim.get("beginRange", "0"),))
            if pdim["unit"] == "Quantity":
                price += getPricePerUnit(pdim) / (nyear * 12)
            elif pdim["unit"] == "Hrs":
                price += getPricePerUnit(pdim) * 24 * 30
            else:
                raise ValueError("bad price record: %r" % pdim)
        priceMap[rname] = price

    pdata = list(ondemand[0]["priceDimensions"].values())
    if pdata[0]["unit"] != "Hrs":
        raise Exception("invalid price unit: %r" % pdata[0]["unit"])
    priceunit = getPricePerUnit(pdata[0])
    price = priceunit * 24 * 30
    priceMap["ondemand"] = price

    sortedMap = {}
    for k in sorted(priceMap):
        sortedMap[k] = roundFloat(priceMap[k])
    return sortedMap


def getPrice(rec):
    pmap = getPriceMap(rec)
    if PRICE_KEY in pmap:
        return pmap[PRICE_KEY]
    return -1


def getMem(rec):
    """Return memory in GBs as float.
    """
    info = rec["product"]["attributes"]
    return float(info.get("memory").split()[0].replace(",", ""))


def getNet(rec):
    """Return network bandwidth in Gbps.
    """
    info = rec["product"]["attributes"]
    net = info.get("networkPerformance")
    if not net:
        return "-"
    if net in OLD_NET:
        return OLD_NET[net]
    parts = net.split()
    if parts[-1] == "Gigabit":
        gbps = parts[-2]
    elif parts[-1] == "Megabit":
        gbps = int(parts[-2]) // 1000
    else:
        return net
    if parts[0] in ["Up"]:
        return "<%s" % gbps
    return "%s" % gbps

def getNetBW(rec):
    """Return network bandwidth in Gbps.
    """
    info = rec["product"]["attributes"]
    net = info.get("networkPerformance")
    if not net:
        return "-"
    if net in OLD_NET:
        return float(OLD_NET[net].replace('~', ''))
    parts = net.split()
    if parts[-1] == "Gigabit":
        return float(parts[-2])
    elif parts[-1] == "Megabit":
        return float(parts[-2]) // 1000
    else:
        return int(net, 10)


def getEbsNet(rec):
    """Return EBS bandwidth in Gbps.
    """
    info = rec["product"]["attributes"]
    ebsnet = info.get("dedicatedEbsThroughput")
    if not ebsnet:
        return "-"
    parts = ebsnet.split()
    if parts[-1] in BWMULT:
        xebsnet = "%.1f" % (float(parts[-2]) * BWMULT[parts[-1]])
        if parts[0] in ("Up", "Upto"):
            xebsnet = "<" + xebsnet
        return xebsnet
    return ebsnet


def getEBSBW(rec):
    """Return EBS bandwidth in Gbps.
    """
    info = rec["product"]["attributes"]
    ebsnet = info.get("dedicatedEbsThroughput")
    if not ebsnet:
        return 0
    parts = ebsnet.split()
    if parts[-1] in BWMULT:
        return (float(parts[-2]) * BWMULT[parts[-1]])
    return float(ebsnet)


def getArch(rec):
    """Return arch type (intel/amd/arm).
    """
    info = rec["product"]["attributes"]
    if info["physicalProcessor"].startswith("Intel "):
        return "intel"
    if info["physicalProcessor"].startswith("High Frequency Intel "):
        return "intel"
    if info["physicalProcessor"].startswith("AMD EPYC "):
        return "amd"
    if info["physicalProcessor"].startswith("AWS Graviton"):
        return "arm"
    if info["physicalProcessor"].startswith("Variable"):
        return "intel"
    raise Exception("unknown cpu: %s" % info["physicalProcessor"])


def getClockSpeed(rec):
    """Return clock speed as float.
    """
    info = rec["product"]["attributes"]
    xspeed = info.get("clockSpeed")
    if xspeed:
        return float(xspeed.split()[-2])
    fspeed = CLOCK_SPEED.get(info["physicalProcessor"])
    if fspeed is not None:
        return fspeed
    return 0.1


def getLocalStorage(rec):
    """Return local SSD storage in GBs.
    """
    info = rec["product"]["attributes"]
    storage = info["storage"]
    if storage.lower() == "ebs only":
        return 0, 0, 0

    parts = storage.split()
    if parts[1] == "x":
        a = int(parts[0])
        b = int(parts[2].replace(",", ""))
        return a, b, a * b
    if parts[1:] == ["GB", "NVMe", "SSD"]:
        a = 1
        b = int(parts[0])
        return a, b, a * b
    raise Exception("cannot parse storage: %r" % storage)


def getFeatures(rec):
    """Return list of CPU features.
    """
    info = rec["product"]["attributes"]
    pfeat = info.get("processorFeatures", "").replace(",", " ").replace(";", " ").split()
    return pfeat


def getRegion(rec):
    """Return region name based on location desc.
    """
    return rec["product"]["attributes"]["regionCode"]


def convert(rec):
    """Convert AWS record to table record.
    """
    info = rec["product"]["attributes"]
    price = getPrice(rec)
    mem = getMem(rec)
    speed = getClockSpeed(rec)
    local = getLocalStorage(rec)
    xebsnet = getEbsNet(rec)

    if mem < 1 or (mem > 3 and mem < 4):
        mem = "%.02f" % mem
    else:
        mem = str(int(mem))

    if speed == 0:
        xspeed = "-"
    else:
        xspeed = "%.1f" % speed

    if local[0] == 0:
        xlocal = "-"
    else:
        xlocal = "%dx%d" % (local[0], local[1])

    notes = []
    if info["currentGeneration"] != "Yes":
        notes.append("Obsolete")
    if info.get("enhancedNetworkingSupported") == "Yes":
        if "ENA" not in CPU_FEATURES_HIDE:
            notes.append("ENA")
    notes.extend([f for f in getFeatures(rec) if f not in CPU_FEATURES_HIDE])

    if has_hw_pmu(info["instanceType"]):
        notes.append("PMU")

    xtask = info["instanceFamily"].split()[0]
    if info.get("gpu"):
        xtask += "-" + info["gpu"]

    nsf = info.get("normalizationSizeFactor", "NA")
    if nsf == "NA":
        nsf = "NA"
    elif len(nsf) > 4:
        nsf = "%.1f" % float(nsf)

    return {
        "instance": f"{info['instanceType']} ({nsf})",
        "region": getRegion(rec),
        "price": f"{price:.02f}",
        "vcpu": info["vcpu"],

        "clock": xspeed,
        "mem": mem,
        "net": getNet(rec),
        "ebsnet": xebsnet,

        "local": xlocal,
        "task": xtask,
        "cpu": CPU_CODES.get(info["physicalProcessor"], "NEW: " + info["physicalProcessor"]),
        "note": ", ".join(notes),
    }

TABLE_HEADER = {
    "instance": "Instance",
    "region": "Region",
    "price": "Price/m",
    "vcpu": "vCPU",

    "clock": "Clock",
    "mem": "Mem",
    "net": "NetBW",
    "ebsnet": "EBSBW",

    "local": "Local",
    "task": "Task",
    "cpu": "Hardware",
    "note": "Note",
}

TABLE_COLALIGN = [
    "left", "left", "right", "right",
    "right", "right", "right", "right",
    "left", "left", "left", "left",
]


def parseRange(v):
    """Parse range from command-line arg.
    """
    MANY = 1 << 24
    if not v:
        return -MANY, MANY
    tmp = v.split("..")
    if len(tmp) == 1:
        r = float(v)
        return r, r
    s1, s2 = tmp
    if not s1:
        s1 = 0
    if not s2:
        s2 = MANY
    return float(s1), float(s2)


def fnmatchList(val, patlist):
    """Compare value to pattern list.
    """
    if patlist is None:
        return True
    for pat in patlist:
        if fnmatch.fnmatchcase(val, pat):
            return True
    return False


def setupFilter(args):
    """Parse filter args from command line.
    """
    global PRICE_KEY

    p = argparse.ArgumentParser(description="List VM type info.")
    p.add_argument("--mem", help="memory range (min..max)")
    p.add_argument("--cpu", help="cpu range (min..max)")
    p.add_argument("--gpu", help="gpu range (min..max)")
    p.add_argument("--ebs", help="ebs range (min..max)")
    p.add_argument("--net", help="net range (min..max)")
    p.add_argument("--size", help="size range (min..max)")
    p.add_argument("--arch", help="arches (intel,amd,arm,all)")
    p.add_argument("--gen", help="generation (current,old,all)")
    p.add_argument("--features", help="generation (avx,avx2,avx512,turbo,deep)")
    p.add_argument("--clock", help="clockspeed range (min..max)")
    p.add_argument("--local", help="local storage (min..max)")
    p.add_argument("--price", help="price range (min..max)")
    p.add_argument("--region", help="list of region (patterns)")
    p.add_argument("--ignore", help="list of vm types to ignore (patterns)")
    p.add_argument("--tenancy", help="tenancy (Shared/Host/Dedicated)", default="Shared")
    p.add_argument("--task", help="task (geNeral/Memory/Storage/Compute/Fpga/Gpu/Video/mL/Umicro)")
    p.add_argument("-s", help="standard (current gen)", action="store_true", dest="standard")
    p.add_argument("-n", help="standard + ignore old vms", dest="onlynew", action="store_true")
    p.add_argument("-x", help="x86 only (intel, amd)", dest="x86", action="store_true")
    p.add_argument("-a", help="ARM only", dest="arm", action="store_true")
    p.add_argument("-r", help="Use reserved pricing /[13][npa][sc]/", dest="reserved")

    g = p.add_argument_group('alternative commands')
    g.add_argument("-R", help="Show region descriptions", dest="showRegions", action="store_true")
    g.add_argument("-P", help="Show reserved prices", dest="showReserved", action="store_true")
    g.add_argument("--show-pmu", help="Show PMU list", dest="showPMU", action="store_true")

    g = p.add_argument_group('output options')
    g.add_argument("--format", help="Output format (default: presto)", default="presto")

    p.add_argument("vmtype", help="specific vm types (patterns)", nargs="*")
    ns = p.parse_args(args)

    if ns.reserved:
        a = ns.reserved
        assert a[0] in "13" and a[1] in "npa" and a[2] in "sc"
        PRICE_KEY = "reserved/%s/%s/%s" % (
            RES_ARG_MAP[ns.reserved[0]],
            RES_ARG_MAP[ns.reserved[2]],
            RES_ARG_MAP[ns.reserved[1]],
        )
    return Filter(ns)


class Filter:
    """Filter object.
    """
    def __init__(self, ns):
        self.format = ns.format

        if ns.region:
            self.region = ns.region.split(",")
        else:
            self.region = ["eu-west-1"]
        if ns.ignore:
            self.ignore_vms = ns.ignore.split(",")
        else:
            self.ignore_vms = []

        if "all" in self.region:
            self.region = None

        self.tenancy = ns.tenancy.capitalize()
        self.mem_min, self.mem_max = parseRange(ns.mem)
        self.cpu_min, self.cpu_max = parseRange(ns.cpu)
        self.clock_min, self.clock_max = parseRange(ns.clock)
        self.local_min, self.local_max = parseRange(ns.local)
        self.price_min, self.price_max = parseRange(ns.price)
        self.gpu_min, self.gpu_max = parseRange(ns.gpu)
        self.size_min, self.size_max = parseRange(ns.size)
        self.ebs_min, self.ebs_max = parseRange(ns.ebs)
        self.net_min, self.net_max = parseRange(ns.net)

        self.arches = None
        self.gen = "all"
        self.features = None
        self.vms = None

        if ns.standard or ns.onlynew:
            self.gen = "current"
        if ns.onlynew:
            self.ignore_vms.append("c4.*")
            self.ignore_vms.append("d2.*")
            self.ignore_vms.append("m4.*")
            self.ignore_vms.append("r4.*")
            self.ignore_vms.append("t2.*")
            self.ignore_vms.append("x1.*")
            self.ignore_vms.append("x1e.*")

            self.ignore_vms.append("f1.*")
            self.ignore_vms.append("g3.*")
            self.ignore_vms.append("g3s.*")
            self.ignore_vms.append("h1.*")
            self.ignore_vms.append("i3.*")
            self.ignore_vms.append("p2.*")
            self.ignore_vms.append("p3.*")

            self.ignore_vms.append("a1.*")

        if ns.x86:
            self.arches = ["amd", "intel"]
        elif ns.arm:
            self.arches = ["arm"]

        if ns.arch:
            self.arches = ns.arch.split(",")
            if "all" in self.arches:
                self.arches = None

        if ns.gen:
            self.gen = ns.gen

        if ns.features:
            self.features = ns.features.lower().split(",")

        if ns.vmtype:
            self.vms = ns.vmtype

        self.showReserved = ns.showReserved
        self.showPMU = ns.showPMU
        self.showRegions = ns.showRegions

        self.task = ns.task.lower() if ns.task else ""

    def match(self, rec):
        """Return True if record matches.
        """
        info = rec["product"]["attributes"]

        if not fnmatchList(getRegion(rec), self.region):
            return False

        if not fnmatchList(info["instanceType"], self.vms):
            return False
        if fnmatchList(info["instanceType"], self.ignore_vms):
            return False

        if info["tenancy"] != self.tenancy:
            return False
        if info["capacitystatus"] != "Used":
            return False

        mem = getMem(rec)
        cpu = int(info["vcpu"])
        speed = getClockSpeed(rec)
        local = getLocalStorage(rec)[2]
        gpu = int(info.get("gpu", "0"))
        normalizationSizeFactor = info.get("normalizationSizeFactor", "NA")
        if normalizationSizeFactor == "NA":
            normalizationSizeFactor = "0"
        size = float(normalizationSizeFactor)
        net = getNetBW(rec)
        ebs = getEBSBW(rec)

        if mem < self.mem_min or mem > self.mem_max:
            return False
        if cpu < self.cpu_min or cpu > self.cpu_max:
            return False
        if speed < self.clock_min or speed > self.clock_max:
            return False
        if local < self.local_min or local > self.local_max:
            return False
        if size < self.size_min or size > self.size_max:
            return False
        if gpu < self.gpu_min or gpu > self.gpu_max:
            return False
        if net < self.net_min or net > self.net_max:
            return False
        if ebs < self.ebs_min or ebs > self.ebs_max:
            return False

        if self.gen:
            if self.gen == "current":
                if info["currentGeneration"] != "Yes":
                    return False
            elif self.gen == "old":
                if info["currentGeneration"] == "Yes":
                    return False
            elif self.gen != "all":
                return False

        if self.arches and getArch(rec) not in self.arches:
            return False

        if self.features:
            pfeat = [p.lower() for p in getFeatures(rec)]
            for f in self.features:
                if f not in pfeat:
                    return False

        price = getPrice(rec)
        if price < self.price_min or price > self.price_max:
            return False

        if self.task:
            xtask = info["instanceFamily"].split()[0]
            if TASK_CODES[xtask] not in self.task:
                return False

        return True


def getSortKey(rec):
    """Return key for stable order.
    """
    info = rec["product"]["attributes"]
    return (getPrice(rec), info["instanceType"], info["location"])


def showReserved(selected):
    res = {}
    for rec in selected:
        info = rec["product"]["attributes"]
        name = info["instanceType"]
        res[name] = getPriceMap(rec)
    print(json.dumps(res, indent=2))


def natsort_key(s, rc=re.compile(r'\d+|\D+')):
    """Split string to numeric and non-numeric fragments."""
    #return [not f[0].isdigit() and f or int(f, 10) for f in rc.findall(s)]
    return [not f[0].isdigit() and f or ('%09d' % int(f, 10)) for f in rc.findall(s)]


vm_sort_suffix = {
    'nano': '0x0nano',
    'micro': '0x1micro',
    'small': '0x2small',
    'medium': '0x3medium',
    'large': '0x4large',
    'xlarge': '1xlarge',
}

def vmtype_key(s):
    a, b = s.split('.', 1)
    return (natsort_key(vm_sort_suffix.get(b, b)), natsort_key(a))


def showPMU(selected):
    """Return key for stable order.
    """
    got = {}
    for rec in selected:
        vm_type = rec['product']['attributes']['instanceType']
        got[vm_type] = has_hw_pmu(vm_type)

    for vm_type in sorted(got, key=vmtype_key):
        print(f"{vm_type}: {got[vm_type]}")


def showRegions(selected):
    collect = set()
    for rec in selected:
        info = rec["product"]["attributes"]
        collect.add((info["regionCode"], info["location"]))
    print(tabulate.tabulate(list(sorted(collect)), (), "plain"))


def load_json_stream(f):
    BLOCKSIZE = 412*1024
    CHUNKSIZE = 16*1024
    decoder = json.JSONDecoder()
    skip_rc = re.compile(r"[ \r\n\t,]+", re.A)

    def skip(buf, pos):
        m = skip_rc.match(buf, pos)
        return m.end() if m else pos

    buf = ""
    pos = 0
    first = True
    while True:
        blk = f.read(BLOCKSIZE)
        if not blk:
            break
        buf = buf[pos:] + blk
        pos = 0

        if first:
            pos = skip(buf, pos)
            if buf[pos] != "[":
                raise ValueError(f"expect list, got {buf[pos]!r}")
            pos = skip(buf, pos + 1)
            first = False

        cutpos = len(buf) - CHUNKSIZE
        while pos < cutpos:
            try:
                obj, pos = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError:
                CHUNKSIZE *= 2
                break
            pos = skip(buf, pos)
            yield obj

    while pos < len(buf) and buf[pos] != "]":
        obj, pos = decoder.raw_decode(buf, pos)
        pos = skip(buf, pos)
        yield obj


def open_json(fn):
    gzfn = fn + ".gz"
    if os.path.isfile(gzfn):
        return gzip.open(gzfn, 'rt')
    return open(fn, 'r')


def load_json(fn):
    with open_json(fn) as f:
        return json.load(f)


def main():
    """Launcher.
    """
    top = os.path.dirname(os.path.realpath(__file__))
    cache_dir = os.path.join(top, "cache")
    cache_dir = os.environ.get("PRICING_CACHE_DIR", cache_dir)
    flt = setupFilter(sys.argv[1:])
    src = os.path.join(cache_dir, "ec2.all.json")

    if flt.showRegions:
        showRegions(load_json(src))
        return

    with open_json(src) as f:
        selected = sorted(
            (
                rec for rec in load_json_stream(f)
                if flt.match(rec)
            ),
            key=getSortKey
        )

    if flt.showReserved:
        showReserved(selected)
    elif flt.showPMU:
        showPMU(selected)
    else:
        rows = [TABLE_HEADER]
        rows.extend(convert(rec) for rec in selected)
        args = {
            "tablefmt": flt.format,
            "disable_numparse": True,
            "colalign": TABLE_COLALIGN,
        }
        # work around tabulate crash with firstrow+0rows
        if len(rows) > 1:
            args["headers"] = "firstrow"
        txt = tabulate.tabulate(rows, **args)
        print(txt)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, IOError):
        sys.exit(1)

