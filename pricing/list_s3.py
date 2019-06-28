#! /usr/bin/env python3

"""List S3 variants.
"""

import json

data = json.load(open('cache/s3.all.json'))

regions = set()
voltypes = set()
classes = set()
for rec in data:
    prod = rec['product']
    att = prod['attributes']
    #if prod.get("productFamily") != "Storage":
    #    continue
    #if att.get("locationType") != "AWS Region":
    #    continue
    if att.get("storageClass") != "Intelligent-Tiering":
        continue
    #if att.get("volumeType") != "Glacier Deep Archive":
    #    continue
    if att.get("location") != 'EU (Ireland)':
        continue

    classes.add(att.get('storageClass'))
    regions.add(att.get('location'))
    voltypes.add(att.get('volumeType'))

    print(json.dumps(rec, indent=2))

print(sorted(regions))
print(sorted(voltypes))
print(sorted(classes))
