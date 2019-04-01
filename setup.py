
from setuptools import setup

import re

vrx = r"""^__version__ *= *['"]([^'"]+)['"]"""
src = open("vmtool/__init__.py").read()
ver = re.search(vrx, src, re.M).group(1)

ldesc = open("README.rst").read().strip()
sdesc = ldesc.split('\n')[0].split(' - ')[1].strip()


setup(
    name="vmtool",
    version=ver,
    description=sdesc,
    long_description=ldesc,
    packages=["vmtool"],
    install_requires=["boto3", "sysca"],
    entry_points={"console_scripts": ["vmtool=vmtool.run:main"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Systems Administration",
    ]
)

