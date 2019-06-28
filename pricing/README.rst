Pricing scripts
===============

Test price filtering.  Perhaps merge it to main vmtool later.

Usage::

    $ ./fetch_cache.py
    $ ./list_vms.py --region='eu-west-*' m5.large
     Instance     | Region    | Price/m | vCPU | ECU | Clock | Mem | NetBW | EBSBW | Local | Task    | Hardware   | Note
    --------------+-----------+---------+------+-----+-------+-----+-------+-------+-------+---------+------------+-------------------
     m5.large (4) | eu-west-1 |   77.04 |    2 |   8 |   2.5 |   8 |  < 10 | < 2.1 |     - | General | X5 Skylake | ENA, AVX2, AVX512
     m5.large (4) | eu-west-2 |   79.92 |    2 |   8 |   2.5 |   8 |  < 10 | < 2.1 |     - | General | X5 Skylake | ENA, AVX2, AVX512
     m5.large (4) | eu-west-3 |   80.64 |    2 |   8 |   2.5 |   8 |  < 10 | < 2.1 |     - | General | X5 Skylake | ENA, AVX2, AVX512

