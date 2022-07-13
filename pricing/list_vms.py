#! /usr/bin/env python3

"""Show AWS instance pricing with optional filtering.
"""

import argparse
import fnmatch
import json
import os.path
import re
import sys
import gzip

import botocore.session


#
# region code to desc maps
#
# https://github.com/boto/botocore/blob/develop/botocore/data/endpoints.json
# https://aws.amazon.com/about-aws/global-infrastructure/regions_az/
# https://aws.amazon.com/about-aws/global-infrastructure/localzones/locations/
# https://aws.amazon.com/wavelength/locations/
#
AWS_ENDPOINTS = botocore.session.get_session().get_data("endpoints")
REGION_TO_DESC = {
    r: rv["description"].replace("Europe", "EU")
    for part in AWS_ENDPOINTS["partitions"]
        for r, rv in part["regions"].items()
}
REGION_TO_DESC.update({
    "af-south-1": "Africa (Cape Town)",
    "ap-east-1": "Asia Pacific (Hong Kong)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-southeast-3": "Asia Pacific (Jakarta)",
    "eu-north-1": "EU (Stockholm)",
    "eu-south-1": "EU (Milan)",
    "me-south-1": "Middle East (Bahrain)",
    "us-gov-east-1": "AWS GovCloud (US-East)",
    "us-gov-west-1": "AWS GovCloud (US-West)",

    # AWS Local Zones
    "us-east-1-atl-1a": "US East (Atlanta)",
    "us-east-1-bos-1": "US East (Boston)",
    "us-east-1-chi-1a": "US East (Chicago)",
    "us-east-1-dfw-1a": "US East (Dallas)",
    "us-east-1-iah-1": "US East (Houston)",
    "us-east-1-mci-1a": "US East (Kansas City 2)",
    "us-east-1-mia-1": "US East (Miami)",
    "us-east-1-msp-1a": "US East (Minneapolis)",
    "us-east-1-nyc-1a": "US East (New York City)",
    "us-east-1-phl-1a": "US East (Philadelphia)",
    "us-west-2-den-1a": "US West (Denver)",
    "us-west-2-las-1a": "US West (Las Vegas)",
    "us-west-2-lax-1a": "US West (Los Angeles)",
    "us-west-2-pdx-1a": "US West (Portland)",
    "us-west-2-phx-1a": "US West (Phoenix)",
    "us-west-2-sea-1a": "US West (Seattle)",

    # Bell Wavelength Zones
    "ca-central-1-wl1-yto-wlz-1": "Canada (BELL) - Toronto",

    # KDDI Wavelength Zones
    "ap-northeast-1-wl1-kix-wlz-1": "Asia Pacific (KDDI) - Osaka",
    "ap-northeast-1-wl1-nrt-wlz-1": "Asia Pacific (KDDI) - Tokyo",

    # SK Telecom Wavelength Zones
    "ap-northeast-2-wl1-cjj-wlz-1": "Asia Pacific (SKT) - Daejeon",
    "ap-northeast-2-wl1-sel-wlz-1": "Asia Pacific (SKT) - Seoul",

    # Vodafone Wavelength Zones
    "eu-central-1-wl1-ber-wlz-1": "Europe (Vodafone) - Berlin",
    "eu-central-1-wl1-dtm-wlz-1": "Europe (Vodafone) - Dortmund",
    "eu-central-1-wl1-muc-wlz-1": "Europe (Vodafone) - Munich",
    "eu-west-2-wl1-lon-wlz-1": "Europe (Vodafone) - London",

    # Verizon Wavelength Zones
    "us-east-1-wl1-atl-wlz-1": "US East (Verizon) - Atlanta",
    "us-east-1-wl1-bna-wlz-1": "US East (Verizon) - Nashville",
    "us-east-1-wl1-bos-wlz-1": "US East (Verizon) - Boston",
    "us-east-1-wl1-chi-wlz-1": "US East (Verizon) - Chicago",
    "us-east-1-wl1-clt-wlz-1": "US East (Verizon) - Charlotte",
    "us-east-1-wl1-dfw-wlz-1": "US East (Verizon) - Dallas",
    "us-east-1-wl1-dtw-wlz-1": "US East (Verizon) - Detroit",
    "us-east-1-wl1-iah-wlz-1": "US East (Verizon) - Houston",
    "us-east-1-wl1-mia-wlz-1": "US East (Verizon) - Miami",
    "us-east-1-wl1-msp-wlz-1": "US East (Verizon) - Minneapolis",
    "us-east-1-wl1-nyc-wlz-1": "US East (Verizon) - New York",
    "us-east-1-wl1-tpa-wlz-1": "US East (Verizon) - Tampa",
    "us-east-1-wl1-was-wlz-1": "US East (Verizon) - Washington DC",
    "us-west-2-wl1-den-wlz-1": "US West (Verizon) - Denver",
    "us-west-2-wl1-las-wlz-1": "US West (Verizon) - Las Vegas",
    "us-west-2-wl1-lax-wlz-1": "US West (Verizon) - Los Angeles",
    "us-west-2-wl1-phx-wlz-1": "US West (Verizon) - Phoenix",
    "us-west-2-wl1-sea-wlz-1": "US West (Verizon) - Seattle",
    "us-west-2-wl1-sfo-wlz-1": "US West (Verizon) - San Francisco Bay Area",
})
DESC_TO_REGION = {v: k for k, v in REGION_TO_DESC.items()}

# CPU feature words
CPU_FEATURES = ["AVX", "AVX2", "AVX512", "Turbo", "Deep"]
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
]

EPYC_V1 = "E1 Naples"
EPYC_V2 = "E2 Rome"
EPYC_V3 = "E3 Milan"

AWS_GRAVITON = "G1 ARMv8"
AWS_GRAVITON2 = "G2 ARMv82"
AWS_GRAVITON3 = "G3 ARMv85"

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
    "Intel Xeon Scalable (Skylake)": xeon(5, "P-8176M"),
    "Intel Xeon Scalable (Icelake)": xeon(8, "P-8375C?"),
    "Intel Xeon 8375C (Ice Lake)": xeon(8, "P-8375C"),
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
    if 1:
        return pfeat
    res = []
    for f in CPU_FEATURES:
        if f in pfeat:
            res.append(f)
    return res


def getRegion(rec):
    """Return region name based on location desc.
    """
    info = rec["product"]["attributes"]
    return DESC_TO_REGION.get(info["location"], info["location"])


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

    if info["ecu"] == "NA":
        xecu = ""
    elif info["ecu"] == "Variable":
        xecu = "~"
    elif "." in info["ecu"]:
        xecu = int(float(info["ecu"]))
    else:
        xecu = info["ecu"]

    xtask = info["instanceFamily"].split()[0]
    if info.get("gpu"):
        xtask += "-" + info["gpu"]

    nsf = info.get("normalizationSizeFactor", "NA")
    if nsf == "NA":
        nsf = "NA"
    elif len(nsf) > 4:
        nsf = "%.1f" % float(nsf)

    return {
        "instanceType": info["instanceType"],
        "mem": mem,
        "net": getNet(rec),
        "price": price,
        "vcpu": info["vcpu"],
        "local": xlocal,
        "clock": xspeed,
        "note": ", ".join(notes),
        "cpu": CPU_CODES.get(info["physicalProcessor"], "NEW: " + info["physicalProcessor"]),
        "task": xtask,
        "ebsnet": xebsnet,
        "ecu": xecu,
        "gpu": info.get("gpu", ""),
        "region": getRegion(rec),
        "normalizationSizeFactor": nsf,
    }


TABLE_FORMAT = {
    "Instance": "{instanceType:<} ({normalizationSizeFactor})",
    "Region": "{region:<}",
    "Price/m": "{price:.02f}",
    "vCPU": "{vcpu}",
    #"ECU": "{ecu}",
    "Clock": "{clock}",
    "Mem": "{mem}",
    "NetBW": "{net}",
    "EBSBW": "{ebsnet}",
    "Local": "{local}",
    "Task": "{task:<}",
    "Hardware": "{cpu:<}",
    "Note": "{note:<}",
}


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

    p.add_argument("vmtype", help="specific vm types (patterns)", nargs="*")
    ns = p.parse_args(args)

    if ns.showRegions:
        for reg in sorted(REGION_TO_DESC):
            print("%-10s %s" % (reg, REGION_TO_DESC[reg]))
        sys.exit(0)

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


def showTable(meta, data_list):
    """Generic table printer.
    """
    widths = {}
    lines = []

    for hdr, fmts in meta.items():
        widths[hdr] = len(hdr)

    for rec in data_list:
        line = []
        for hdr, fmt in meta.items():
            v = fmt.format(**rec)
            if len(v) > widths[hdr]:
                widths[hdr] = len(v)
            line.append(v)
        lines.append(tuple(line))

    hdrs = []
    fmts = []
    for hdr, fmt in meta.items():
        mx = widths[hdr]
        hdrs.append(hdr.ljust(mx))
        if "<" in fmt:
            fmts.append("%%-%ds" % mx)
        else:
            fmts.append("%%%ds" % mx)

    line_fmt = " %s " % " | ".join(fmts)
    hdr_line = " %s " % " | ".join(hdrs)
    sep_line = re.sub("[^+]", "-", hdr_line.replace("|", "+"))

    print(hdr_line.rstrip())
    print(sep_line.rstrip())
    for line in lines:
        print((line_fmt % line).rstrip())


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


def load_json(fn):
    gzfn = fn + ".gz"
    if os.path.isfile(gzfn):
        with gzip.open(gzfn, 'rt') as f:
            return json.load(f)
    with open(fn, 'r') as f:
        return json.load(f)


def main():
    """Launcher.
    """
    top = os.path.dirname(os.path.realpath(__file__))
    cache_dir = os.path.join(top, "cache")
    cache_dir = os.environ.get("PRICING_CACHE_DIR", cache_dir)
    flt = setupFilter(sys.argv[1:])
    src = os.path.join(cache_dir, "ec2.all.json")
    data = load_json(src)
    selected = [rec for rec in data if flt.match(rec)]
    selected = sorted(selected, key=getSortKey)
    if flt.showReserved:
        showReserved(selected)
    else:
        converted = [convert(rec) for rec in selected]
        showTable(TABLE_FORMAT, converted)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, IOError):
        sys.exit(1)

