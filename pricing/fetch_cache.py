#! /usr/bin/env python3

"""Store large API results on disk.

- https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/using-pelong.html
- https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_pricing_GetProducts.html

Bulk:

- https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/index.json

"""

import json
import os
import sys
import gzip

import boto3.session
import botocore.session

# region code to desc maps
AWS_ENDPOINTS = botocore.session.get_session().get_data("endpoints")
REGION_TO_DESC = {
    r: rv["description"].replace("Europe", "EU")
    for part in AWS_ENDPOINTS["partitions"]
        for r, rv in part["regions"].items()
}
DESC_TO_REGION = {v: k for k, v in REGION_TO_DESC.items()}


def get_products(pclient, **kwargs):
    """Fetch pricing based on filter.
    """
    filters = []
    for k, v in kwargs.items():
        if v is not None:
            filters.append({"Type": "TERM_MATCH", "Field": k, "Value": v})

    res = []
    pager = pclient.get_paginator("get_products").paginate
    for page in pager(FormatVersion="aws_v1", ServiceCode=kwargs.get("ServiceCode"), Filters=filters):
        for rec in page.get("PriceList") or []:
            res.append(json.loads(rec))
    return res


def write_cache(fn, pclient, **kwargs):
    """Fetch and write as json.
    """
    res = get_products(pclient, **kwargs)
    with gzip.open(fn + ".gz", "wt") as f:
        json.dump(res, f, separators=(",", ":"))


def get_region_desc(region, partition="aws"):
    """Return region description based on region code.
    """
    if region == "all":
        return None
    return REGION_TO_DESC[region]


def dump_cache(pclient, region):
    """Write prices on disk
    """
    REGION_DESC = get_region_desc(region)

    EC2_FILTER = {
        #"locationType": "AWS Region",   # AWS Region/AWS Outposts/AWS Local Zone/AWS Wavelength Zone
        #"location": REGION_DESC,
        "ServiceCode": "AmazonEC2",
        # Compute Instance, Compute Instance (bare metal),
        # CPU Credits, Data Transfer, Dedicated Host, EBS direct API Requests,
        # Elastic Graphics, Fast Snapshot Restore, Fee, IP Address,
        # Load Balancer, Load Balancer-Application, Load Balancer-Network,
        # NAT Gateway, Provisioned Throughput, Storage, Storage Snapshot, System Operation,
        "productFamily": "Compute Instance",
        "operatingSystem": "Linux",     # NA/Linux/Windows/RHEL/SUSE/Red Hat Enterprise Linux with HA
        "licenseModel": "No License required",  # NA/No License required/Bring your own license
        "preInstalledSw": "NA",     # NA/SQL Web/SQL Std/SQL Ent
        "capacitystatus": "Used",   # Used/UnusedCapacityReservation/AllocatedCapacityReservation
        "tenancy": "Shared",        # Shared/Dedicated/Host
    }

    EBS_FILTER = {
        "locationType": "AWS Region",
        "location": REGION_DESC,
        "ServiceCode": "AmazonEC2",
        "productFamily": "Storage",
    }

    S3_FILTER = {
        "locationType": "AWS Region",
        "location": REGION_DESC,
        "ServiceCode": "AmazonS3",
    }

    os.makedirs("cache", exist_ok=True)
    write_cache("cache/ec2.%s.json" % region, pclient, **EC2_FILTER)
    write_cache("cache/ebs.%s.json" % region, pclient, **EBS_FILTER)
    write_cache("cache/s3.%s.json" % region, pclient, **S3_FILTER)


def main():
    profile_name = None
    pclient = boto3.session.Session(profile_name=profile_name, region_name="us-east-1").client("pricing")

    args = sys.argv[1:]
    if not args:
        args = ["all"]

    for r in args:
        print("Fetching %s" % r)
        dump_cache(pclient, r)


if __name__ == "__main__":
    main()

