"""AWS backend for vmtool.
"""

import argparse
import binascii
import datetime
import errno
import gzip
import io
import ipaddress
import json
import logging
import os
import os.path
import pprint
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tarfile
import time
import uuid

from fnmatch import fnmatch

import boto3.session
import boto3.s3.transfer
import botocore.session

from vmtool.certs import load_cert_config
from vmtool.config import Config, NoOptionError
from vmtool.envconfig import load_env_config, find_gittop
from vmtool.scripting import EnvScript, UsageError
from vmtool.tarfilter import TarFilter
from vmtool.terra import tf_load_output_var, tf_load_all_vars
from vmtool.util import fmt_dur
from vmtool.util import printf, eprintf, time_printf, print_json, local_cmd, run_successfully
from vmtool.util import ssh_add_known_host, parse_console, rsh_quote, as_unicode
from vmtool.xglob import xglob


# /usr/share/doc/cloud-init/userdata.txt
USERDATA = """\
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===RND==="

--===RND===
Content-Type: text/cloud-boothook; charset="us-ascii"
Content-Disposition: attachment; filename="early-init.sh"
Content-Transfer-Encoding: 7bit

#! /bin/sh

echo "$INSTANCE_ID: RND" > /dev/urandom
( ls -l --full-time /var/log; dmesg; ) | sha512sum > /dev/urandom
echo "$INSTANCE_ID: entropy added" > /dev/console

--===RND===
Content-Type: text/x-shellscript; charset="us-ascii"
Content-Disposition: attachment; filename="late-init.sh"
Content-Transfer-Encoding: 7bit

#! /bin/sh

addgroup -q --system vmsudo

test -f /etc/sudoers.d/00-vmsudo || {
  echo "%vmsudo ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/00-vmsudo
  chmod 440 /etc/sudoers.d/00-vmsudo
}

AUTHORIZED_USER_CREATION

--===RND===--
"""


SSH_USER_CREATION = '''\
if ! grep -q '^{user}:' /etc/passwd; then
  echo "Adding user {user}"
  adduser -q --gecos {user} --disabled-password {user} < /dev/null
  install -d -o {user} -g {user} -m 700  ~{user}/.ssh
  echo "{pubkey}" > ~{user}/.ssh/authorized_keys
  chmod 600 ~{user}/.ssh/authorized_keys
  chown {user}:{user} ~{user}/.ssh/authorized_keys
  for grp in {auth_groups}; do
    adduser -q {user} $grp
  done
fi
'''

# replace those with root specified by image
ROOT_DEV_NAMES = ('root', 'xvda', '/dev/sda1')


def show_commits(old_id, new_id, dirs, cwd):
    cmd = ['git', '--no-pager', 'shortlog', '--no-merges', old_id + '..' + new_id]
    if dirs:
        cmd.append('--')
        cmd.extend(dirs)
    subprocess.call(cmd, cwd=cwd)


def mk_sshuser_script(user, auth_groups, pubkey):
    return SSH_USER_CREATION.format(user=user, auth_groups=' '.join(auth_groups), pubkey=pubkey)


class VmCmd:
    """Sub-command names used internally in vmtool.
    """
    PREP: str = 'prep'
    FAILOVER_PROMOTE_SECONDARY: str = 'failover_promote_secondary'

    TAKEOVER_PREPARE_PRIMARY: str = 'takeover_prepare_primary'
    TAKEOVER_PREPARE_SECONDARY: str = 'takeover_prepare_secondary'
    TAKEOVER_FINISH_PRIMARY: str = 'takeover_finish_primary'
    TAKEOVER_FINISH_SECONDARY: str  = 'takeover_finish_secondary'

    DROP_NODE_PREPARE: str = 'drop_node_prepare'

class VmState:
    PRIMARY: str = 'primary'
    SECONDARY: str = 'secondary'


class VmTool(EnvScript):
    __doc__ = __doc__

    _boto_sessions = None
    _boto_clients = None

    _pricing_cache = {}
    _endpoints = None

    _vm_map = None

    role_name = None
    env_name = None     # name of current env
    full_role = None
    ssh_dir = None

    new_commit = None
    old_commit = None
    availability_zone = None

    log = logging.getLogger('vmtool')

    def startup(self):
        logging.getLogger('boto3').setLevel(logging.WARNING)
        logging.getLogger('botocore').setLevel(logging.WARNING)

    def reload(self):
        """Reload config.
        """
        self.git_dir = find_gittop()

        # ~/.vmtool
        ssh_dir = os.path.expanduser('~/.vmtool')
        if not os.path.isdir(ssh_dir):
            os.mkdir(ssh_dir, stat.S_IRWXU)

        keys_dir = os.environ.get('VMTOOL_KEY_DIR',  os.path.join(self.git_dir, 'keys'))
        if not keys_dir or not os.path.isdir(keys_dir):
            raise UsageError('Set vmtool config dir: VMTOOL_KEY_DIR')

        ca_log_dir = os.environ.get('VMTOOL_CA_LOG_DIR')
        if not ca_log_dir or not os.path.isdir(ca_log_dir):
            raise UsageError('Set vmtool config dir: VMTOOL_CA_LOG_DIR')

        env = os.environ.get('VMTOOL_ENV_NAME', '')
        if self.options.env:
            env = self.options.env
        if not env:
            raise UsageError('No envronment set: either set VMTOOL_ENV_NAME or give --env=ENV')

        env_name = env
        self.full_role = env
        if '.' in env:
            env_name, self.role_name = env.split('.')
        self.env_name = env_name
        if self.options.role:
            self.role_name = self.options.role
            self.full_role = '%s.%s' % (self.env_name, self.role_name)

        self.ca_log_dir = ca_log_dir
        self.keys_dir = keys_dir
        self.ssh_dir = ssh_dir

        self.cf = load_env_config(self.full_role, {
            'FILE': self.conf_func_file,
            'KEY': self.conf_func_key,
            'TF': self.conf_func_tf,
            'TFAZ': self.conf_func_tfaz,
            'PRIMARY_VM': self.conf_func_primary_vm,
            'NETWORK': self.conf_func_network,
            'NETMASK': self.conf_func_netmask,
            'MEMBERS': self.conf_func_members,
        })
        self.process_pkgs()

        self._region = self.cf.get('region')
        self.ssh_known_hosts = os.path.join(self.ssh_dir, 'known_hosts')
        self.is_live = self.cf.getint('is_live', 0)

        if self.options.az is not None:
            self.availability_zone = self.options.az
        else:
            self.availability_zone = self.cf.getint('availability_zone', 0)

        # fill vm_ordered_disk_names
        disk_map = self.get_disk_map()
        if disk_map:
            api_order = []
            size_order = []
            for dev in disk_map:
                size = disk_map[dev]["size"]
                count = disk_map[dev]["count"]
                if size and dev not in ROOT_DEV_NAMES:
                    for i in range(count):
                        name = f"{dev}.{i}" if count > 1 else dev
                        size_order.append( (size, i, name) )
                        api_order.append(name)
            size_order.sort()
            self.cf.set("vm_disk_names_size_order", ", ".join([elem[2] for elem in size_order]))
            self.cf.set("vm_disk_names_api_order", ", ".join(api_order))

    _gpg_cache = None
    def load_gpg_file(self, fn):
        if self._gpg_cache is None:
            self._gpg_cache = {}
        if fn in self._gpg_cache:
            return self._gpg_cache[fn]
        if self.options.verbose:
            printf("GPG: %s", fn)
        # file data directly
        if not os.path.isfile(fn):
            raise UsageError("GPG file not found: %s" % fn)
        data = self.popen(['gpg', '-q', '-d', '--batch', fn])
        res = as_unicode(data)
        self._gpg_cache[fn] = res
        return res

    def load_gpg_config(self, fn, main_section):
        realfn = os.path.join(self.keys_dir, fn)
        if not os.path.isfile(realfn):
            raise UsageError("GPG file not found: %s" % realfn)
        data = self.load_gpg_file(realfn)
        cf = Config(main_section, None)
        cf.cf.read_string(data, source=realfn)
        return cf

    def popen(self, cmd, input_data=None, **kwargs):
        """Read command stdout, check for exit code.
        """
        pipe = subprocess.PIPE
        if input_data is not None:
            p = subprocess.Popen(cmd, stdin=pipe, stdout=pipe, stderr=pipe, **kwargs)
        else:
            p = subprocess.Popen(cmd, stdout=pipe, stderr=pipe, **kwargs)
        out, err = p.communicate(input_data)
        if p.returncode != 0:
            raise Exception("command failed: %r - %r" % (cmd, err.strip()))
        return out

    def load_command_docs(self):
        doc = self.__doc__.strip()
        doc = ''
        grc = re.compile(r'Group: *(\w+)')
        cmds = []

        for fn in sorted(dir(self)):
            if fn.startswith('cmd_'):
                fobj = getattr(self, fn)
                docstr = (getattr(fobj, '__doc__', '') or '').strip()
                mgrp = grc.search(docstr)
                grpname = mgrp and mgrp.group(1) or ''
                lines = docstr.split('\n')
                fdoc = lines[0]
                cmd = fn[4:].replace('_', '-')
                cmds.append((grpname, cmd, fdoc))

        for sect in self.cf.sections():
            if sect.startswith('cmd.') or sect.startswith('alias.'):
                cmd = sect.split('.', 1)[1]
                desc = ''
                grpname = ''
                if self.cf.cf.has_option(sect, 'desc'):
                    desc = self.cf.cf.get(sect, 'desc')
                if self.cf.cf.has_option(sect, 'group'):
                    grpname = self.cf.cf.get(sect, 'group')
                fdoc = desc.strip().split('\n')[0]
                cmds.append((grpname, cmd, desc))

        cmds.sort()
        last_grp = None
        sep = ''
        for grpname, cmd, fdoc in cmds:
            if grpname != last_grp:
                doc += sep + '%s commands:\n' % (grpname or 'ungrouped')
                last_grp = grpname
                sep = '\n'
            doc += '  %-30s - %s\n' % (cmd, fdoc)
        return doc

    def cmd_help(self):
        """Show help about commands.

        Group: info
        """
        doc = self.load_command_docs()
        printf(doc)

    def init_argparse(self, parser=None):
        if parser is None:
            parser = argparse.ArgumentParser(prog='vmtool')
        p = super(VmTool, self).init_argparse(parser)
        #doc = self.__doc__.strip()
        #p.set_usage(doc)
        p.add_argument("--env", help="Set environment name (default comes from VMTOOL_ENV_NAME)")
        p.add_argument("--role", help="Set role name (default: None)")
        p.add_argument("--host", help="Use host instead detecting")
        p.add_argument("--all", action="store_true", help="Make command work over all envs")
        p.add_argument("--ssh-key", help="Use different SSH key")
        p.add_argument("--all-role-vms", action="store_true", help="Run command on all vms for role")
        p.add_argument("--all-role-fo-vms", action="store_true", help="Run command on all failover vms for role")
        p.add_argument("--running", action="store_true", help="Show only running instances")
        p.add_argument("--az", type=int, help="Set availability zone")
        p.add_argument("--tmux", action="store_true", help="Wrap session in tmux")
        return p

    def get_boto3_session(self, region=None):
        if not region:
            region = self._region
        if self._boto_sessions is None:
            self._boto_sessions = {}
        if self._boto_sessions.get(region) is None:
            profile_name = self.cf.get('aws_profile_name', '') or None
            key = self.cf.get('aws_access_key', '') or None
            sec = self.cf.get('aws_secret_key', '') or None
            self._boto_sessions[region] = boto3.session.Session(
                profile_name=profile_name, region_name=region,
                aws_access_key_id=key, aws_secret_access_key=sec)
        return self._boto_sessions[region]

    def get_boto3_client(self, svc, region=None):
        if svc == 'pricing':
            region = 'us-east-1'    # provided only in 'us-east-1' and 'ap-south-1'
        elif not region:
            region = self._region
        if self._boto_clients is None:
            self._boto_clients = {}

        scode = (region, svc)
        if scode not in self._boto_clients:
            session = self.get_boto3_session(region)
            self._boto_clients[scode] = session.client(svc)
        return self._boto_clients[scode]

    def get_elb(self, region=None):
        """Get cached ELB connection.
        """
        return self.get_boto3_client('elb', region)

    def get_s3(self, region=None):
        """Get cached S3 connection.
        """
        return self.get_boto3_client('s3', region)

    def get_ddb(self, region=None):
        """Get cached DynamoDB connection.
        """
        return self.get_boto3_client('dynamodb', region)

    def get_route53(self):
        """Get cached ELB connection.
        """
        return self.get_boto3_client('route53')

    def get_ec2_client(self, region=None):
        return self.get_boto3_client('ec2', region)

    def get_pricing_client(self, region=None):
        return self.get_boto3_client('pricing', region)

    def pager(self, client, method, rname):
        """Create pager function for looping over long results.
        """
        lister = client.get_paginator(method)

        def pager(**kwargs):
            for page in lister.paginate(**kwargs):
                for rec in page.get(rname) or []:
                    yield rec
        return pager

    def ec2_iter_instances(self, region=None, **kwargs):
        client = self.get_ec2_client(region)
        pager = self.pager(client, 'describe_instances', 'Reservations')
        for rv in pager(**kwargs):
            for vm in rv['Instances']:
                yield vm

    def ec2_iter(self, func, result, region=None, **kwargs):
        client = self.get_ec2_client(region)
        pager = self.pager(client, func, result)
        for rec in pager(**kwargs):
            yield rec

    def s3_iter(self, func, result, region=None, **kwargs):
        client = self.get_s3(region)
        pager = self.pager(client, func, result)
        for rec in pager(**kwargs):
            yield rec

    def pricing_iter_services(self, **kwargs):
        """Pricing.Client.describe_services"""
        client = self.get_pricing_client()
        pager = self.pager(client, 'describe_services', 'Services')
        for rec in pager(**kwargs):
            yield rec

    def pricing_iter_products(self, **kwargs):
        """Pricing.Client.get_products"""
        client = self.get_pricing_client()
        pager = self.pager(client, 'get_products', 'PriceList')
        for rec in pager(**kwargs):
            yield json.loads(rec)

    def pricing_iter_attribute_values(self, **kwargs):
        """Pricing.Client.get_attribute_values"""
        client = self.get_pricing_client()
        pager = self.pager(client, 'get_attribute_values', 'AttributeValues')
        for rec in pager(**kwargs):
            yield rec

    def get_region_desc(self, region):
        if self._endpoints is None:
            self._endpoints = botocore.session.get_session().get_data('endpoints')
            if self._endpoints['version'] != 3:
                raise Exception("unsupported endpoints version: %d" % self._endpoints['version'])
        for part in self._endpoints['partitions']:
            if part['partition'] == 'aws': # aws, aws-us-gov, aws-cn
                desc = part['regions'][region]['description']
                desc = desc.replace('Europe', 'EU') # botocore vs. us-east-1/pricing bug
                return desc
        raise Exception("did not find 'aws' partition")

    VOL_TYPE_DESC = {
        'standard': 'Magnetic',
        'gp2': 'General Purpose',
        'gp3': 'General Purpose',
        'io1': 'Provisioned IOPS',
        'io2': 'Provisioned IOPS',
        'st1': 'Throughput Optimized HDD',
        'sc1': 'Cold HDD',
    }
    VOL_TYPES = tuple(VOL_TYPE_DESC)
    VOL_ENC_TYPES = tuple("enc-" + x for x in VOL_TYPES)

    def get_volume_desc(self, vol_type):
        return self.VOL_TYPE_DESC[vol_type]

    STORAGE_FILTER = {
        'STANDARD': {'productFamily': 'Storage', 'volumeType': 'Standard'},
        'STANDARD_IA': {'productFamily': 'Storage', 'volumeType': 'Standard - Infrequent Access'},
        'ONEZONE_IA': {'productFamily': 'Storage', 'volumeType': 'One Zone - Infrequent Access'},
        'GLACIER': {'productFamily': 'Storage', 'volumeType': 'Amazon Glacier'},
        # deprecated
        'REDUCED_REDUNDANCY': {'productFamily': 'Storage', 'volumeType': 'Reduced Redundancy'},
        # buggy pricing data
        'DEEP_ARCHIVE': {'volumeType': 'Glacier Deep Archive'},
        'INTELLIGENT_TIERING': {'storageClass': 'Intelligent-Tiering'},
    }

    def get_storage_filter(self, storage_class):
        """Return filter for pricing query.
        """
        #storageClass: ['Archive', 'General Purpose', 'Infrequent Access', 'Intelligent-Tiering', 'Non-Critical Data', 'Staging', 'Tags']
        #volumeType: ['Amazon Glacier', 'Glacier Deep Archive', 'Intelligent-Tiering Frequent Access',
        #             'Intelligent-Tiering Infrequent Access', 'Intelligent-Tiering', 'One Zone - Infrequent Access',
        #             'Reduced Redundancy', 'Standard - Infrequent Access', 'Standard', 'Tags']
        return self.STORAGE_FILTER[storage_class]

    def get_cached_pricing(self, **kwargs):
        """Fetch pricing for single product, cache based on filter.

        ServiceCode=AmazonEC2
            productFamily
                CPU Credits, Compute Instance (bare metal), Compute Instance, Data Transfer, Dedicated Host,
                Elastic Graphics, Fee, IP Address, Load Balancer-Application, Load Balancer-Network, Load Balancer,
                NAT Gateway, Storage Snapshot, Storage, System Operation
        """
        filters = []
        for k, v in kwargs.items():
            filters.append({'Type': 'TERM_MATCH', 'Field': k, 'Value': v})
        cache_key = json.dumps(kwargs, sort_keys=True)
        if cache_key not in self._pricing_cache:
            res = []
            for rec in self.pricing_iter_products(FormatVersion='aws_v1', ServiceCode=kwargs.get('ServiceCode'), Filters=filters):
                res.append(rec)
            if len(res) != 1:
                raise UsageError("Broken pricing filter: expect 1 row, got %d, cache_key: %s" % (
                    len(res), cache_key)
                )
            self._pricing_cache[cache_key] = res[0]
        return self._pricing_cache[cache_key]

    def get_offer_price(self, offer, unit):
        prices = list(offer['priceDimensions'].values())
        if len(prices) != 1:
            raise Exception('prices: expected one value, got %d' % len(prices))
        if prices[0]['unit'] != unit:
            raise Exception('prices: expected %s, got %s' % (unit, prices[0]['unit']))
        return float(prices[0]['pricePerUnit']['USD'])

    def get_vm_pricing(self, region, vmtype):
        """Return simplified price object for vm cost.
        """

        def loadOnDemand(vmdata):
            """Return hourly price for ondemand instances."""
            offers = list(vmdata['terms']['OnDemand'].values())
            if len(offers) != 1:
                raise Exception('OnDemand.offers: expected one value, got %d' % len(offers))
            return self.get_offer_price(offers[0], 'Hrs')

        def loadReserved(vmdata):
            """Return hourly price for reserved (no-upfront/standard/1yr) instances."""
            got = []
            for offer in vmdata['terms']['Reserved'].values():
                atts = offer['termAttributes']
                opt = atts['PurchaseOption']        # No Upfront, All Upfront, Partial Upfront
                cls = atts['OfferingClass']         # standard, convertible
                lse = atts['LeaseContractLength']   # 1yr, 3yr
                if (opt, cls, lse) == ('No Upfront', 'standard', '1yr'):
                    got.append(self.get_offer_price(offer, 'Hrs'))
            if len(got) != 1:
                raise Exception('expected one value, got %d' % len(got))
            return got[0]

        vmdata = self.get_cached_pricing(
            ServiceCode='AmazonEC2',
            locationType='AWS Region',
            location=self.get_region_desc(region),
            productFamily='Compute Instance',
            preInstalledSw='NA',        # NA, SQL Ent, SQL Std, SQL Web
            operatingSystem='Linux',    # NA, Linux, RHEL, SUSE, Windows
            tenancy='Shared',           # NA, Dedicated, Host, Reserved, Shared
            capacitystatus='Used',      # NA, Used, AllocatedCapacityReservation, AllocatedHost, UnusedCapacityReservation
            instanceType=vmtype,
        )

        return {
            'onDemandHourly': loadOnDemand(vmdata),
            'reservedHourly': loadReserved(vmdata),
        }

    def get_volume_pricing(self, region, vol_type):
        """Return numeric price for volume cost.
        """
        p = self.get_cached_pricing(
            ServiceCode='AmazonEC2',
            locationType='AWS Region',
            location=self.get_region_desc(region),
            productFamily='Storage',
            volumeType=self.get_volume_desc(vol_type))

        offers = list(p['terms']['OnDemand'].values())
        if len(offers) != 1:
            raise Exception('expected one value, got %d' % len(offers))
        return self.get_offer_price(offers[0], 'GB-Mo')

    def get_s3_pricing(self, region, storage_class, size):
        """Return numeric price for volume cost.
        """
        p = self.get_cached_pricing(
            ServiceCode='AmazonS3',
            locationType='AWS Region',
            location=self.get_region_desc(region),
            **self.get_storage_filter(storage_class))

        offers = list(p['terms']['OnDemand'].values())
        if len(offers) != 1:
            raise Exception('expected one value, got %d' % len(offers))

        # S3 prices are in segments
        total = 0
        for pdim in offers[0]['priceDimensions'].values():
            if pdim['unit'] != 'GB-Mo':
                raise Exception('expected GB-Mo, got %s' % pdim['unit'])
            beginRange = int(pdim['beginRange'])
            if pdim['endRange'] != 'Inf':
                endRange = int(pdim['endRange'])
            else:
                endRange = size

            if size < beginRange:
                continue
            elif size > endRange:
                curblk = endRange - beginRange
            else:
                curblk = size - beginRange
            total += curblk * float(pdim['pricePerUnit']['USD'])
        return total

    def cmd_debug_pricing(self):
        svcNames = [svc['ServiceCode'] for svc in self.pricing_iter_services()]
        print('ServiceCode=%s' % svcNames)

        svclist = list(self.pricing_iter_services(ServiceCode='AmazonEC2'))
        print('%s=%s' % (svclist[0]['ServiceCode'], json.dumps(svclist[0], indent=2)))

        for svc in svclist:
            code = svc['ServiceCode']
            for att in sorted(svc['AttributeNames']):
                vlist = []
                cnt = 0
                for val in self.pricing_iter_attribute_values(ServiceCode=code, AttributeName=att):
                    if cnt > 100:
                        vlist.append('...')
                        break
                    vlist.append(val['Value'])
                    cnt += 1
                print('%s.%s = %r' % (code, att, vlist))

    def route53_iter_rrsets(self, **kwargs):
        client = self.get_route53()
        pager = self.pager(client, 'list_resource_record_sets', 'ResourceRecordSets')
        return pager(**kwargs)

    def sgroups_lookup(self, sgs_list):
        # manual lookup for sgs
        sg_ids = []
        for sg in sgs_list:
            if sg.startswith('sg-'):
                sg_ids.append(sg)
            else:
                raise UsageError("deprecated non-id sg: %r" % sg)
        return sg_ids

    def show_vm_list(self, vm_list, adrmap=None, dnsmap=None):
        adrmap = adrmap or {}
        dnsmap = dnsmap or {}

        use_colors = sys.stdout.isatty()
        if use_colors:
            if sys.platform.startswith('win'):
                use_colors = False

        vm_list = sorted(vm_list, key=lambda vm: vm['LaunchTime'])

        extra_verbose = self.options.verbose and self.options.verbose > 1
        vol_map = {}
        if extra_verbose:
            vol_map = self.get_volume_map(vm_list)

        for vm in vm_list:
            if not self.options.all:
                if not self._check_tags(vm.get('Tags')):
                    continue
            eip = ""
            name = ""
            extra_lines = []
            if vm.get('InstanceId') in adrmap:
                eip += " EIP=%s" % adrmap[vm['InstanceId']]
            if vm.get('PrivateIpAddress') in dnsmap:
                eip += " IDNS=" + dnsmap[vm['PrivateIpAddress']]
            if vm.get('PublicIpAddress') in dnsmap:
                eip += " PDNS=" + dnsmap[vm['PublicIpAddress']]
            if len(vm['NetworkInterfaces']) > 1:
                for iface in vm['NetworkInterfaces']:
                    att = iface['Attachment']
                    sep = ''
                    eni = 'net#%s - %s - IP=' % (att['DeviceIndex'], att['Status'])
                    for adr in iface['PrivateIpAddresses']:
                        eni += sep + adr['PrivateIpAddress']
                        sep = ','
                        if adr.get('Association'):
                            eni += ' (%s)' % (adr['Association']['PublicIp'])
                    if iface['Attachment']['DeleteOnTermination']:
                        eni += ' del=yes'
                    else:
                        eni += ' del=no'
                        eni += ' ENI=' + iface['NetworkInterfaceId']
                    if iface.get('Description'):
                        eni += ' desc=' + iface.get('Description')
                    extra_lines.append(eni)

            # add colors
            c1 = ""
            c2 = ""
            if use_colors:
                if eip:
                    if vm['State']['Name'] == 'running':
                        c1 = "\033[32m"     # green
                    else:
                        c1 = "\033[35m"     # light purple
                elif vm['State']['Name'] == 'running':
                    c1 = "\033[31m"         # red

                # close color
                if c1:
                    c2 = "\033[0m"

            vm_env = '-'
            vm_role = ''
            for tag in vm.get('Tags', []):
                if tag['Key'] == 'Env':
                    vm_env = tag['Value']
                elif tag['Key'] == 'Role':
                    vm_role = tag['Value']

            name += " Env=" + vm_env
            if vm_role:
                name += '.' + vm_role

            name += ' type=%s' % vm['InstanceType']
            tags = ""
            for tagname in ['Date', 'Commit', 'PYI', 'DBI', 'JSI', 'SYS']:
                for tag in vm.get('Tags', []):
                    if tag['Key'] == tagname:
                        tags += ' %s=%s' % (tagname, tag['Value'])

            az = vm['Placement']['AvailabilityZone']
            if az[-2].isdigit() and az[-1].islower():
                name += ' AZ=%d' % (ord(az[-1]) - ord('a'))
            else:
                name += ' AZ=%s' % az

            int_ip = ''
            if vm.get('PrivateIpAddress'):
                int_ip = ' ip=%s' % vm['PrivateIpAddress']

            # one-line output
            printf("%s [%s%s%s]%s%s%s%s", vm['InstanceId'], c1, vm['State']['Name'], c2, name, tags, int_ip, eip)

            if self.options.verbose and extra_lines:
                for xln in extra_lines:
                    printf('  %s', xln)
                printf('')

            if not extra_verbose:
                continue

            # verbose output
            printf('  LaunchTime: %s', vm['LaunchTime'])
            if vm.get('RootDeviceName'):
                printf('  RootDevice: %s - %s', vm['RootDeviceType'], vm['RootDeviceName'])
            if vm.get('IamInstanceProfile'):
                printf('  IamInstanceProfile: %s', vm['IamInstanceProfile']['Arn'])
            printf('  Zone=%s', vm['Placement']['AvailabilityZone'])
            if vm.get('PublicIpAddress'):
                printf("  PublicIpAddress: %s / %s", vm['PublicIpAddress'], (vm.get('PublicDnsName') or '-'))
            if vm.get('PrivateIpAddress'):
                printf("  PrivateIpAddress: %s / %s", vm['PrivateIpAddress'], (vm.get('PrivateDnsName') or '-'))
            printf("  Groups: %s", ', '.join([g['GroupName'] for g in vm['SecurityGroups']]))
            for iface in vm.get('NetworkInterfaces', []):
                printf('  NetworkInterface id=%s', iface.get('NetworkInterfaceId'))
                printf('    Association=%s', iface.get('Association'))
                printf('    PrivateIpAddresses=%s', iface.get('PrivateIpAddresses'))
            for bdev in vm.get('BlockDeviceMappings', []):
                ebs = bdev.get('Ebs')
                if ebs:
                    vol = vol_map[ebs['VolumeId']]
                    printf('  BlockDeviceMapping name=%s size=%d type=%s vol=%s',
                            bdev.get('DeviceName'),
                            vol['Size'],
                            vol['VolumeType'],
                            ebs['VolumeId'])
                    #print_json(vol)
                else:
                    printf('  BlockDeviceMapping name=%s', bdev.get('DeviceName'))
                    print_json(bdev)

            printf("  Tags:")
            for tag in sorted(vm.get('Tags', []), key=lambda tag: tag['Key']):
                printf('    %s=%s', tag['Key'], tag['Value'])
            for k in ('State', 'StateReason', 'StateTransitionReason'):
                if vm.get(k):
                    printf('  %s: %s', k, vm[k])
            if self.options.verbose > 2:
                print_json(vm)
            printf('')


    def get_volume_map(self, vm_list):
        vmap = {}
        vols = set()
        for vm in vm_list:
            if not self.options.all:
                if not self._check_tags(vm.get('Tags')):
                    continue
            for bdev in vm.get('BlockDeviceMappings'):
                ebs = bdev.get('Ebs')
                if ebs:
                    vols.add(ebs['VolumeId'])

        #printf("get_volume_map: %r", vols)
        for vol in self.ec2_iter('describe_volumes', 'Volumes', VolumeIds=list(vols)):
            vmap[vol['VolumeId']] = vol
        return vmap

    def get_ssh_kfile(self):
        # load encrypted key
        if self.options.ssh_key:
            gpg_fn = self.options.ssh_key
        else:
            gpg_fn = self.cf.get('ssh_privkey_file')
        gpg_fn = os.path.join(self.keys_dir, gpg_fn)
        kdata = self.load_gpg_file(gpg_fn).strip()

        raw_fn = os.path.basename(gpg_fn).replace('.gpg', '')

        fn = os.path.join(self.ssh_dir, raw_fn)

        # check existing key
        if os.path.isfile(fn):
            curdata = open(fn, 'r').read().strip()
            if curdata == kdata:
                return fn
            os.remove(fn)

        printf("Extracting keyfile %s to %s", gpg_fn, fn)
        fd = os.open(fn, os.O_CREAT | os.O_WRONLY, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(kdata + "\n")
        return fn

    def ssh_cmdline(self, use_admin=False):
        if self.cf.getboolean('ssh_admin_user_disabled', False):
            ssh_user = self.cf.get('user')
        elif use_admin:
            ssh_user = self.cf.get('ssh_admin_user')
        else:
            ssh_user = self.cf.get('user')

        ssh_debug = '-q'
        if self.options.verbose:
            ssh_debug = '-v'

        ssh_options = shlex.split(self.cf.get('ssh_options', ''))

        return ['ssh', ssh_debug, '-i', self.get_ssh_kfile(), '-l', ssh_user,
                '-o', 'UserKnownHostsFile=' + self.ssh_known_hosts] + ssh_options

    def vm_exec_tmux(self, vm_id, cmdline, use_admin=False, title=None):
        if self.options.tmux:
            tmux_command = shlex.split(self.cf.get('tmux_command'))
            if title:
                tmux_command = [a.replace('{title}', title) for a in tmux_command]
            cmdline = tmux_command + cmdline
        self.vm_exec(vm_id, cmdline, use_admin=use_admin)

    def vm_exec(self, vm_id, cmdline, stdin=None, get_output=False, check_error=True, use_admin=False):
        logging.debug("EXEC@%s: %s", vm_id, cmdline)
        self.put_known_host_from_tags(vm_id)

        # only image default user works?
        if not self.cf.getboolean('ssh_user_access_works', False):
            use_admin = True

        ssh = self.ssh_cmdline(use_admin=use_admin)

        if not stdin and not get_output and sys.stdout.isatty():        # pylint:disable=no-member
            ssh.append('-t')

        if self.options.host:
            # use host directly, dangerous
            hostname = self.options.host
        elif self.cf.getboolean('ssh_internal_ip_works', False):
            vm = self.vm_lookup(vm_id)
            hostname = vm.get('PrivateIpAddress')
        else:
            # FIXME: vm with ENI
            vm = self.vm_lookup(vm_id)
            #hostname = vm.get('PublicDnsName')
            hostname = vm.get('PublicIpAddress')
            last_idx = 600 * 1024 * 1024 * 1024
            if len(vm['NetworkInterfaces']) > 1:
                for iface in vm['NetworkInterfaces']:
                    #print_json(iface)
                    idx = iface['Attachment']['DeviceIndex']
                    if 1 or idx < last_idx:
                        assoc = iface.get('Association')
                        if assoc:
                            hostname = assoc['PublicIp']
                            last_idx = idx
                            break
                eprintf("SSH to %s", hostname)
        if not hostname:
            logging.error("Public DNS nor ip not yet available for node %r", vm_id)
            #print_json(vm)
            sys.exit(1)

        ssh.append(hostname)
        if isinstance(cmdline, str):
            ssh += [cmdline]
        else:
            logging.debug('EXEC: rsh_quote=%r', cmdline)
            ssh += rsh_quote(cmdline)
        out = None
        kwargs = {}
        if stdin is not None:
            kwargs['stdin'] = subprocess.PIPE
        if get_output:
            kwargs['stdout'] = subprocess.PIPE
        logging.debug('EXEC: cmd=%r', ssh)
        logging.debug('EXEC: kwargs=%r', kwargs)
        if kwargs:
            p = subprocess.Popen(ssh, **kwargs)
            out, err = p.communicate(stdin)
            ret = p.returncode
        else:
            ret = subprocess.call(ssh)
        if ret != 0:
            if check_error:
                raise UsageError("Errorcode: %r" % ret)
            return None
        return out

    def vm_rsync(self, *args, use_admin=False):
        primary_id = None
        nargs = []
        ids = []
        for a in args:
            t = a.split(':', 1)
            if len(t) == 1:
                nargs.append(a)
                continue
            if t[0]:
                vm_id = t[0]
            elif primary_id:
                vm_id = primary_id
            else:
                vm_id = primary_id = self.get_primary_vms()[0]
            vm = self.vm_lookup(vm_id)
            self.put_known_host_from_tags(vm_id)
            vm = self.vm_lookup(vm_id)
            if self.cf.getboolean('ssh_internal_ip_works', False):
                hostname = vm.get('PrivateIpAddress')
            else:
                hostname = vm.get('PublicIpAddress')
            a = "%s:%s" % (hostname, t[1])
            nargs.append(a)
            ids.append(vm_id)

        ssh_list = self.ssh_cmdline(use_admin=use_admin)
        ssh_cmd = ' '.join(rsh_quote(ssh_list))

        cmd = ['rsync', '-rtz', '-e', ssh_cmd]
        if self.options.verbose:
            cmd.append('-P')
        cmd += nargs
        self.log.debug("rsync: %r", cmd)
        run_successfully(cmd)

    def vm_lookup(self, vm_id, ignore_env=False, cache=True):
        if self._vm_map is None:
            self._vm_map = {}
        if vm_id in self._vm_map and cache:
            return self._vm_map[vm_id]

        for vm in self.ec2_iter_instances(InstanceIds=[vm_id]):
            if vm['State']['Name'] != 'running':
                raise UsageError("VM not running: %s / %r" % (vm_id, vm['State']))
            if not ignore_env:
                if not self._check_tags(vm.get('Tags')):
                    continue
            self._vm_map[vm_id] = vm
            return vm
        raise UsageError("VM not found: %s" % vm_id)

    def new_ssh_key(self, vm_id):
        """Fetch output, parse keys.
        """
        time_printf("Waiting for image copy, boot and SSH host key generation")
        client = self.get_ec2_client()
        keys = None
        time.sleep(30)
        retry = 0
        for i in range(100):
            time.sleep(30)
            # load console buffer from EC2
            for retry in range(3):
                try:
                    cres = client.get_console_output(InstanceId=vm_id)
                    break
                except socket.error as ex:
                    if ex.errno != errno.ETIMEDOUT:
                        raise
            out = cres.get('Output')
            if not out:
                continue
            keys = parse_console(out, ['ssh-ed25519'])
            if keys is not None:
                break
        if not keys:
            raise UsageError("Failed to get SSH keys")

        # set ssh key as tag
        ssh_tags = []
        for n, kval in enumerate(keys):
            ktype = kval[0]
            kcert = kval[1]
            tag = {'Key': ktype, 'Value': kcert}
            ssh_tags.append(tag)
        client.create_tags(Resources=[vm_id], Tags=ssh_tags)

        for vm in self.ec2_iter_instances(InstanceIds=[vm_id]):
            pub_dns = vm.get('PublicDnsName')
            pub_ip = vm.get('PublicIpAddress')

            if pub_ip:
                for tag in ssh_tags:
                    ssh_add_known_host(self.ssh_known_hosts, pub_dns, pub_ip,
                                       tag['Key'], tag['Value'], vm_id)

            priv_dns = vm.get('PrivateDnsName') or None
            priv_ip = vm.get('PrivateIpAddress')
            if priv_ip:
                for tag in ssh_tags:
                    ssh_add_known_host(self.ssh_known_hosts, priv_dns, priv_ip,
                                       tag['Key'], tag['Value'], vm_id)

    def put_known_host_from_tags(self, vm_id):
        """Get ssh keys from tags.
        """
        vm = self.vm_lookup(vm_id)
        iplist = []
        if self.cf.getboolean('ssh_internal_ip_works', False):
            iplist.append(vm['PrivateIpAddress'])
        else:
            for iface in vm['NetworkInterfaces']:
                assoc = iface.get('Association')
                if assoc:
                    ip = assoc['PublicIp']
                    if ip:
                        iplist.append(ip)
            ip = vm.get('PublicIpAddress')
            if ip and ip not in iplist:
                iplist.append(ip)

        old_keys = []
        new_keys = []
        for tag in vm.get('Tags', []):
            k = tag['Key']
            v = tag['Value']
            if k.startswith('ecdsa-'):
                old_keys.append( (k, v) )
            elif k.startswith('ssh-'):
                new_keys.append( (k, v) )

        if new_keys:
            old_keys = []
        dns = None
        for k, v in old_keys + new_keys:
            for ip in iplist:
                ssh_add_known_host(self.ssh_known_hosts, dns, ip, k, v, vm_id)

    def get_env_filters(self):
        """Return default filters based on command-line swithces.
        """
        return self.make_env_filters(role_name=self.role_name, running=self.options.running, allenvs=self.options.all)

    def make_env_filters(self, role_name=None, running=True, allenvs=False):
        """Return filters for instance listing.
        """
        filters = []

        if not allenvs:
            filters.append({'Name': 'tag:Env', 'Values': [self.env_name]})
            if role_name or self.role_name:
                filters.append({'Name': 'tag:Role', 'Values': [role_name or self.role_name]})

        if running:
            filters.append({'Name': 'instance-state-name', 'Values': ['running']})

        return filters


    def get_running_vms(self, role_name=None):
        vmlist = []

        if not role_name:
            role_name = self.role_name
        filters = self.make_env_filters(role_name=role_name, running=True)

        for vm in self.ec2_iter_instances(Filters=filters):
            if not self._check_tags(vm.get('Tags'), force_role=True, role_name=role_name):
                continue
            if vm['State']['Name'] == 'running':
                vmlist.append(vm)
        return vmlist

    def get_dead_primary(self):
        ec2 = self.get_ec2_client()

        eip = self.cf.get('domain_eip', '')
        main_vms = []
        if eip:
            ipfilter = {
                'Name': 'public-ip',
                'Values': [eip]
            }
            res = ec2.describe_addresses(Filters=[ipfilter])
            for addr in res['Addresses']:
                if not addr.get('InstanceId'):
                    continue
                if addr['PublicIp'] == eip:
                    main_vms.append(addr['InstanceId'])
                    break

            if main_vms:
                for vm in self.ec2_iter_instances(Filters=self.get_env_filters(), InstanceIds=main_vms):
                    if not self._check_tags(vm.get('Tags'), True):
                        continue
                    if vm['State']['Name'] != 'running':
                        eprintf("Dead Primary VM for %s is %s", self.full_role, ','.join(main_vms))
                        return main_vms
                    else:
                        raise UsageError('Primary VM still running')
            raise UsageError("Primary VM not found based on EIP")

        dnsmap = self.get_dns_map()
        for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
            if not self._check_tags(vm.get('Tags'), True):
                continue

            if vm.get('PrivateIpAddress') in dnsmap:
                pass
            elif vm.get('PublicIpAddress') in dnsmap:
                pass
            else:
                continue

            if vm['State']['Name'] == 'running':
                raise UsageError('Primary VM still running')
            main_vms.append(vm['InstanceId'])
        if not main_vms:
            raise UsageError("Dead Primary VM not found")
        eprintf("Dead Primary VM for %s is %s", self.full_role, ','.join(main_vms))
        return main_vms

    def get_primary_for_role(self, role_name, instance_id=None):
        filters = self.make_env_filters(role_name=role_name, running=True)
        dns_map = self.get_dns_map(True)
        for vm in self.ec2_iter_instances(Filters=filters):
            if not self._check_tags(vm.get('Tags'), role_name=role_name, force_role=True):
                continue
            if vm['State']['Name'] != 'running':
                continue
            #  ignore IP checks if instance_id is manually provided
            if instance_id is not None:
                if vm['InstanceId'] == instance_id:
                    return vm
            elif vm.get('PrivateIpAddress') in dns_map:
                return vm
            #elif vm.get('PublicIpAddress') in dns_map:
            #    return vm

        raise UsageError("Primary VM not found: %s" % role_name)

    def get_primary_vms(self):
        if self.options.all_role_vms:
            return self.get_all_role_vms()
        if self.options.all_role_fo_vms:
            return self.get_all_role_fo_vms()
        main_vms = self._get_primary_vms()
        if main_vms:
            eprintf("Primary VM for %s is %s", self.full_role, ','.join(main_vms))
            return main_vms
        raise UsageError("Primary VM not found")

    def _get_primary_vms(self):
        ec2 = self.get_ec2_client()
        eip = self.cf.get('domain_eip', '')
        main_vms = []
        if eip:
            ipfilter = {
                'Name': 'public-ip',
                'Values': [eip]
            }
            res = ec2.describe_addresses(Filters=[ipfilter])
            for addr in res['Addresses']:
                if not addr.get('InstanceId'):
                    continue
                if addr['PublicIp'] == eip:
                    main_vms.append(addr['InstanceId'])
                    break

            return main_vms

        internal_hostname = self.cf.get('internal_hostname')
        dnsmap = self.get_dns_map()
        for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
            if not self._check_tags(vm.get('Tags'), True):
                continue
            if vm['State']['Name'] != 'running':
                continue
            if vm.get('PrivateIpAddress') in dnsmap:
                if internal_hostname:
                    dns_name = dnsmap[vm['PrivateIpAddress']].rstrip(".")
                    if dns_name != internal_hostname:
                        continue
                main_vms.append(vm['InstanceId'])
            elif vm.get('PublicIpAddress') in dnsmap:
                main_vms.append(vm['InstanceId'])
        return main_vms

    def get_all_role_vms(self):
        if not self.role_name:
            raise UsageError("Not in a role-based env")

        main_vms = self._get_primary_vms()

        all_vms = []
        for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
            if not self._check_tags(vm.get('Tags'), True):
                continue
            if vm['State']['Name'] != 'running':
                continue

            # prepend primary vms
            if vm['InstanceId'] in main_vms:
                all_vms.insert(0, vm['InstanceId'])
            else:
                all_vms.append(vm['InstanceId'])
        if not all_vms:
            eprintf("No running VMs for %s", self.full_role)
        else:
            eprintf("Running VMs for %s: %s", self.full_role, ' '.join(all_vms))
        return all_vms

    def get_all_role_fo_vms(self):
        if not self.role_name:
            raise UsageError("Not in a role-based env")

        main_vms = self._get_primary_vms()

        all_vms = []
        for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
            if not self._check_tags(vm.get('Tags'), True):
                continue
            if vm['State']['Name'] != 'running':
                continue

            # skip primary vms
            if vm['InstanceId'] in main_vms:
                pass
            else:
                all_vms.append(vm['InstanceId'])
        if not all_vms:
            eprintf("No running failover VMs for %s", self.full_role)
        else:
            eprintf("Running failover VMs for %s: %s", self.full_role, ' '.join(all_vms))
        return all_vms

    def _check_tags(self, taglist, force_role=False, role_name=None):
        if role_name is None:
            role_name = self.role_name
        if not taglist:
            return False

        gotenv = gotrole = False
        for tag in taglist:
            if tag['Key'] == 'Env':
                gotenv = True
                if tag['Value'] != self.env_name:
                    return False
            if tag['Key'] == 'Role':
                gotrole = True
                if role_name and tag['Value'] != role_name:
                    return False
        if not gotenv:
            return False
        if not gotrole and role_name:
            return False
        elif force_role and not role_name:
            return False
        return True

    def get_vm_args(self, args, allow_multi=False):
        """Check if args start with VM ID.

        returns: (vm-id, args)
        """
        if args and args[0][:2] == 'i-':
            vm_list = [args[0]]
            args = args[1:]
        else:
            vm_list = self.get_primary_vms()

        if allow_multi:
            return vm_list, args

        if len(vm_list) != 1:
            raise UsageError("Command does not support multiple vms")
        return vm_list[0], args

    def cmd_show_vms(self, *cmdargs):
        """Show VMs.

        Group: info
        """
        client = self.get_ec2_client()

        adrmap = {}
        res = client.describe_addresses()
        for adr in res['Addresses']:
            if adr.get('InstanceId'):
                adrmap[adr['InstanceId']] = adr['PublicIp']

        dnsmap = self.get_dns_map(True)

        args = {}
        args['Filters'] = self.get_env_filters()
        if cmdargs:
            args['InstanceIds'] = cmdargs

        vm_list = []
        for vm in self.ec2_iter_instances(**args):
            vm_list.append(vm)

        self.show_vm_list(vm_list, adrmap, dnsmap)

    #
    # get_reserved_instances_exchange_quote()
    # accept_reserved_instances_exchange_quote()
    #
    # create_reserved_instances_listing()
    # describe_reserved_instances_listings()
    # cancel_reserved_instances_listing()
    #
    # describe_reserved_instances_offerings()
    # purchase_reserved_instances_offering()
    #
    # describe_reserved_instances()
    # modify_reserved_instances()
    # describe_reserved_instances_modifications()
    #

    def cmd_show_reserved(self, *cmdargs):
        """Show reserved instances.

        Group: pricing
        """
        client = self.get_ec2_client()
        response = client.describe_reserved_instances()
        wres = response['ReservedInstances']
        for rvm in wres:
            tstart = rvm['Start'].isoformat()[:10]
            tend = rvm['End'].isoformat()[:10]
            plist = ','.join(['{Amount}/{Frequency}'.format(**p) for p in rvm['RecurringCharges']])

            printf("{ReservedInstancesId} type={InstanceType} count={InstanceCount} state={State}".format(**rvm))
            printf("  offering: class={OfferingClass} payment=[{OfferingType}] os=[{ProductDescription}] scope={Scope}".format(**rvm))
            printf("  Price: fixed={FixedPrice} usage={UsagePrice} recur=".format(**rvm) + plist)
            printf("  Dur: start=%s end=%s", tstart, tend)

    def show_vmcost(self, region, vmtype, nActive, nReserved, names):
        """Shoe one vmtype stats with pricing.
        """
        nstep = 4
        odCount = 0
        if nActive > nReserved:
            odCount = nActive - nReserved
        price = self.get_vm_pricing(region, vmtype)
        rawMonth = int(nActive * price['onDemandHourly'] * 24 * 30)
        odMonth = int(odCount * price['onDemandHourly'] * 24 * 30)
        rMonth = int(nReserved * price['reservedHourly'] * 24 * 30)
        odPrice = '($%d/m)' % odMonth
        rPrice = '($%d/m)' % rMonth

        odStr = ''
        resStr = ''
        if odCount:
            odStr = 'ondemand: %2d %-9s' % (odCount, odPrice)
        if nReserved:
            resStr = 'reserved: %d %s' % (nReserved, rPrice)
        nfirst = ''
        if names:
            nfirst = '[%s]' % ', '.join(names[:nstep])
            names = names[nstep:]
        printf("  %-12s: running: %2d  %-23s %-23s%s", vmtype, nActive, odStr, resStr, nfirst)
        while names:
            printf("%76s[%s]", ' ', ', '.join(names[:nstep]))
            names = names[nstep:]
        return rawMonth, odMonth + rMonth

    def load_vmenv(self, vm):
        env = None
        role = None
        for tag in vm.get('Tags', []):
            if tag['Key'] == 'Env':
                env = tag['Value']
            elif tag['Key'] == 'Role':
                role = tag['Value']
        if env:
            if role:
                return env + '.' + role
            return env
        return None

    def cmd_show_vmcost(self):
        """Show VM cost.

        Group: pricing
        """
        all_regions = self.cf.getlist('all_regions')
        rawTotal = 0
        total = 0
        for region in all_regions:
            tmap = {}
            envmap = {}
            rmap = {}
            client = self.get_ec2_client(region)

            # scan reserved instances
            for rvm in client.describe_reserved_instances()['ReservedInstances']:
                if rvm['State'] == 'active':
                    vm_type = rvm['InstanceType']
                    if vm_type not in rmap:
                        rmap[vm_type] = 0
                    rmap[vm_type] += rvm['InstanceCount']

            # scan running instances
            flist = [{'Name': 'instance-state-name', 'Values': ['running']}]
            for vm in self.ec2_iter_instances(region=region, Filters=flist):
                vm_type = vm['InstanceType']
                if vm_type not in tmap:
                    tmap[vm_type] = 0
                tmap[vm_type] += 1

                rname = self.load_vmenv(vm)
                if vm_type not in envmap:
                    envmap[vm_type] = set()
                envmap[vm_type].add(rname)

            if not tmap and not rmap:
                continue

            printf('-- %s --', region)
            for vm_type in sorted(tmap):
                names = list(sorted(envmap[vm_type]))
                rawSum, curSum = self.show_vmcost(region, vm_type, tmap[vm_type], rmap.get(vm_type, 0), names)
                rawTotal += rawSum
                total += curSum
            for vm_type in rmap:
                if vm_type not in tmap:
                    rawSum, curSum = self.show_vmcost(region, vm_type, 0, rmap[vm_type], [])
                    rawTotal += rawSum
                    total += curSum
        printf('total: $%d/m  reserved bonus: $%d/m', total, rawTotal - total)

    def cmd_show_ebscost(self):
        """Show disk cost.

        Group: pricing
        """

        def addVol(info, vol):
            vtype = vol['VolumeType']
            if vtype not in info:
                info[vtype] = 0
            info[vtype] += vol['Size']

        def show(name, info, region):
            parts = []
            for t in sorted(info):
                s = '%s=%d' % (t, info[t])
                if not t.startswith('vm-'):
                    p = self.get_volume_pricing(region, t) * info[t]
                    if p < 1:
                        p = 1
                    s += ' ($%d/m)' % int(p)
                parts.append(s)
            if not parts:
                parts = ['-']
            printf('%-20s %s', name+':', ', '.join(parts))

        all_regions = self.cf.getlist('all_regions')
        for region in all_regions:
            printf('-- %s --', region)

            envmap = {}
            vol_map = {}
            totals = {}
            gotVol = set()

            for vol in self.ec2_iter('describe_volumes', 'Volumes', region=region):
                vol_map[vol['VolumeId']] = vol

            for vm in self.ec2_iter_instances(region=region, Filters=[]):
                rname = self.load_vmenv(vm)
                if rname not in envmap:
                    envmap[rname] = {}
                rinfo = envmap[rname]

                sname = 'vm-' + vm['State']['Name']
                if sname not in rinfo:
                    rinfo[sname] = 0
                rinfo[sname] += 1

                for bdev in vm.get('BlockDeviceMappings', []):
                    ebs = bdev.get('Ebs')
                    if ebs:
                        gotVol.add(ebs['VolumeId'])
                        vol = vol_map.get(ebs['VolumeId'])
                        if vol:
                            addVol(totals, vol)
                            addVol(rinfo, vol)
                        else:
                            printf('Missing vol: %s, instance: %s', ebs['VolumeId'], vm['InstanceId'])

            if totals or vol_map:
                for rname in sorted(envmap):
                    info = envmap[rname]
                    show(rname, info, region)
                show('* total', totals, region)

                for vol_id in vol_map:
                    if vol_id not in gotVol:
                        printf("! Lost volume: %s", vol_id)

    def cmd_show_s3cost(self):
        """Show S3 cost.

        Group: pricing
        """

        def show(name, info, region):
            line = ['%-30s' % name]
            for k, v in info.items():
                gbs = int(v / (1024*1024*1024))
                total = self.get_s3_pricing(region, k, gbs)
                line.append('%s=%d ($%d/m)' % (k, int(gbs), total))
            print(' '.join(line))

        all_regions = self.cf.getlist('all_regions')
        for region in all_regions:
            printf('-- %s --', region)
            totals = {}
            for bucket in self.get_s3(region).list_buckets()['Buckets']:
                bucket_name = bucket['Name']
                bucket_info = {}
                for obj in self.s3_iter('list_object_versions', 'Versions', region=region, Bucket=bucket_name):
                    # Size, StorageClass, IsLatest, LastModified
                    sclass = obj['StorageClass']
                    size = obj['Size'] # round to block?
                    bucket_info[sclass] = bucket_info.get(sclass, 0) + size
                for k, v in bucket_info.items():
                    totals[k] = totals.get(k, 0) + v
                show(bucket_name, bucket_info, region)
            show('* total *', totals, region)

    def cmd_show_untagged(self):
        """Show VMs without tags.

        Group: info
        """
        client = self.get_ec2_client()

        adrmap = {}
        res = client.describe_addresses()
        for adr in res['Addresses']:
            if adr.get('InstanceId'):
                adrmap[adr['InstanceId']] = adr['PublicIp']

        dnsmap = self.get_dns_map(True)

        args = {}
        vm_list = []
        for vm in self.ec2_iter_instances(**args):
            if not vm.get('Tags'):
                vm_list.append(vm)

        self.options.all = True
        self.show_vm_list(vm_list, adrmap, dnsmap)

    def cmd_show_lbs(self):
        """Show Elastic Load Balancers.

        Group: info
        """
        client = self.get_elb()
        res = client.describe_load_balancers()
        for lb in res['LoadBalancerDescriptions']:
            printf("Name: %s", lb['DNSName'])
            printf("  SrcSecGroup: %r", lb['SourceSecurityGroup']['GroupName'])
            printf("  ExtraSecGroups: %r", lb['SecurityGroups'])

    def cmd_show_sgs(self):
        """Show security groups.

        Group: info
        """
        client = self.get_ec2_client()
        res = client.describe_security_groups()

        # item, owner_id, region, rules, rules_egress, tags, vpc_id
        for sg in res['SecurityGroups']:
            printf("%s - %s - %s", sg['GroupId'], sg['GroupName'], sg['Description'])
            printf("  RulesIn: %r", len(sg['IpPermissions']))
            printf("  RulesOut: %r", len(sg['IpPermissionsEgress']))
            if sg.get('Tags'):
                printf("  Tags: %r", sg['Tags'])

    def cmd_show_buckets(self):
        """Show S3 buckets.

        Group: s3
        """
        s3 = self.get_s3()
        res = s3.list_buckets()
        for b in res['Buckets']:
            printf("%s", b['Name'])

    def cmd_show_files(self, *blist):
        """Show files in a S3 bucket.

        Group: s3
        """
        cur_bucket = self.cf.get('files_bucket')
        if not blist:
            blist = [cur_bucket]

        for bname in blist:
            eprintf("---- %s ----", bname)
            for kx in self.s3_iter_objects(bname):
                if self.options.verbose:
                    self.s3_show_obj_head(bname, kx['Key'], kx)
                else:
                    printf("%s", kx['Key'])

    def s3_get_obj_head(self, bucket, key):
        return self.get_s3().head_object(Bucket=bucket, Key=key)

    def s3_show_obj_head(self, bucket, key, res):
        printf("%s", key)
        for a in ('ContentLength', 'ContentType', 'ContentEncoding', 'ContentDisposition',
                  'ContentLanguage', 'Metadata', 'CacheControl',
                  'ETag', 'LastModified', 'StorageClass', 'ReplicationStatus',
                  'ServerSideEncryption', 'PartsCount',
                  'SSECustomerKeyMD5', 'SSEKMSKeyId', 'SSECustomerAlgorithm'):
            v = res.get(a)
            if v:
                printf("    %s: %r", a, v)

    def s3_show_obj_info(self, bucket, key, info):
        printf("%s", key)
        for k in info:
            v = info.get(k)
            if isinstance(v, datetime.datetime):
                v = v.isoformat(' ')
            if k != 'Key' and v:
                printf("    %s: %r", k, v)

    def s3_iter_objects(self, bucket, prefix=None):
        s3client = self.get_s3()
        pg_list_objects = s3client.get_paginator('list_objects')

        args = {'Bucket': bucket}
        if prefix:
            args['Prefix'] = prefix

        for pres in pg_list_objects.paginate(**args):
            for obj in pres.get('Contents') or []:
                yield obj

    def s3_iter_object_versions(self, bucket, prefix=None):
        s3client = self.get_s3()
        pg_list_object_versions = s3client.get_paginator('list_object_versions')

        args = {'Bucket': bucket}
        if prefix:
            args['Prefix'] = prefix

        for pres in pg_list_object_versions.paginate(**args):
            for obj in pres.get('Versions') or []:
                yield obj

    def cmd_show_backups(self, *slot_list):
        """Show backup slots in S3.

        Group: backup
        """
        slot_filter = ''

        bucket_name = self.cf.get('backup_aws_bucket')
        pfx = self.cf.get('backup_prefix')
        if slot_list:
            slot_filter = slot_list[0]
            pfx += slot_filter

        summary_output = not self.options.verbose and not slot_filter

        eprintf("---- %s ----", bucket_name)
        slots = {}
        backup_domain = pfx.split('/')[0]
        for kx in self.s3_iter_objects(bucket_name, pfx):
            parts = kx['Key'].split('/')
            if parts[0] != backup_domain:
                continue

            size = kx['Size']
            if parts[2] == 'base':
                slot = '/'.join(parts[1:4])
            else:
                slot = '/'.join(parts[1:3])
            if slot not in slots:
                slots[slot] = 0
            slots[slot] += size
            if not summary_output:
                #head = self.s3_get_obj_head(bucket_name, kx['Key'])
                #self.s3_show_obj_head(bucket_name, kx['Key'], head)
                self.s3_show_obj_info(bucket_name, kx['Key'], kx)

        if summary_output:
            for slot in sorted(slots):
                print("%s: %d GB" % (slot, int(slots[slot] / (1024*1024*1024))))

    def cmd_get_backup(self, *slot_list):
        """Download backup files from S3.

        Group: backup
        """
        s3 = self.get_s3()
        bucket_name = self.cf.get('backup_aws_bucket')
        pfx = self.cf.get('backup_prefix')

        # disable multipart downloads
        tx_config = boto3.s3.transfer.TransferConfig(
            multipart_threshold=16 * 1024 * 1024 * 1024,
            max_concurrency=1)

        if slot_list:
            pfx += slot_list[0]

        eprintf("---- %s ----", bucket_name)
        namelist = []
        for kx in self.s3_iter_objects(bucket_name, pfx):
            namelist.append(kx['Key'])
        namelist.sort()

        cur_fn = None
        last = [0, 0, time.time()]
        for kname in namelist:
            fn, ext = os.path.splitext(kname)
            if ext[1:].isdigit():
                pass
            else:
                fn = kname

            if cur_fn != fn:
                fdir = os.path.dirname(fn)
                if not os.path.isdir(fdir):
                    os.makedirs(fdir, mode=0o700)
                cur_fn = fn

            res = s3.head_object(Bucket=bucket_name, Key=kname)
            total_size = res['ContentLength']

            def progcb(cur_read, total=total_size, kname=kname):
                last[0] += cur_read

                cur = last[0]
                if total:
                    perc = cur * 100.0 / total
                else:
                    perc = 100
                now = time.time()
                if last[1] > 0 and now - last[2] < 2:
                    return
                amount = cur - last[1]
                dur = now - last[2]
                sys.stdout.write('\r%-30s %.1f%% of %d [%.1f kb/s]    ' % (kname, perc, total, amount / (dur * 1024.0)))
                sys.stdout.flush()
                last[1] = cur
                last[2] = now

            last[0], last[1], last[2] = 0, 0, time.time()

            s3.download_file(Bucket=bucket_name, Key=kname, Filename=fn, Callback=progcb, Config=tx_config)
            sys.stdout.write('\n')

    def cmd_clean_backups(self):
        """Clean backup slots in S3.

        Group: backup
        """
        s3client = self.get_s3()

        # keep daily
        days = 6 * 30
        dt_pos = datetime.datetime.utcnow() - datetime.timedelta(days=days)
        min_slot = dt_pos.strftime('%Y/%m/%d')

        bucket_name = self.cf.get('backup_aws_bucket')
        pfx = self.cf.get('backup_prefix')
        rc_test = re.compile(r'^\d\d\d\d/\d\d/\d\d$')

        printf("---- %s ----", bucket_name)
        slots = {}
        del_list = []
        keep_set = set()
        backup_domain = pfx.split('/')[0]
        for kx in self.s3_iter_object_versions(bucket_name, pfx):
            parts = kx['Key'].split(':')[0].split('/')
            if parts[0] != backup_domain:
                continue
            slot = '/'.join(parts[1:])
            if not rc_test.match(slot):
                raise Exception('Unexpected slot format: %r' % slot)
            if slot >= min_slot:
                keep_set.add(slot)
                continue

            ref = {'Key': kx['Key']}
            if kx.get('VersionId'):
                ref['VersionId'] = kx['VersionId']
            del_list.append(ref)

            if len(del_list) >= 500:
                printf("Deleting files: %d", len(del_list))
                s3client.delete_objects(Bucket=bucket_name, Delete={'Objects': del_list, 'Quiet': True})
                del_list = []

        if del_list:
            printf("Deleting files: %d", len(del_list))
            s3client.delete_objects(Bucket=bucket_name, Delete={'Objects': del_list, 'Quiet': True})

        printf("Kept %d slots for %s", len(keep_set), backup_domain)

    def cmd_ls_backups(self):
        """Show backup slots in S3.

        Group: backup
        """
        s3client = self.get_s3()

        bucket_name = self.cf.get('backup_aws_bucket')
        pfx = self.cf.get('backup_prefix')

        smap = {
            'STANDARD': 'S',
            'STANDARD_IA': 'I',
            'ONEZONE_IA': 'Z',
            'GLACIER': 'G',
            'REDUCED_REDUNDANCY': 'R',
        }

        printf("---- %s ----", bucket_name)
        n = 0
        for kx in self.s3_iter_object_versions(bucket_name, pfx):
            #print_json(kx)
            lmod = kx['LastModified']
            size = kx['Size']
            age = kx['IsLatest'] and '!' or '~'
            scls = smap.get(kx['StorageClass'], kx['StorageClass'])
            ver = kx['VersionId']
            printf("%s %s", kx['Key'], scls + age)

    def cmd_ls_files(self):
        """Show backup slots in S3.

        Group: backup
        """
        s3client = self.get_s3()

        bucket_name = self.cf.get('files_bucket')
        pfx = ''

        smap = {
            'STANDARD': 'S',
            'STANDARD_IA': 'I',
            'ONEZONE_IA': 'Z',
            'GLACIER': 'G',
            'REDUCED_REDUNDANCY': 'R',
        }

        eprintf("---- %s ----", bucket_name)
        for kx in self.s3_iter_object_versions(bucket_name, pfx):
            #print_json(kx)
            mtime = kx['LastModified'].isoformat()[:10]
            size = kx['Size']
            age = kx['IsLatest'] and '!' or '~'
            scls = smap.get(kx['StorageClass'], kx['StorageClass'])
            tag = scls + age
            ver = kx['VersionId']
            name = kx['Key']
            printf("mtime=%s tag=%s size=%d key=%s", mtime, tag, size, name)

    def cmd_show_ips(self):
        """Show allocated Elastic IPs.

        Group: info
        """
        client = self.get_ec2_client()
        res = client.describe_addresses()
        for a in res['Addresses']:
            #tags = ['%s: %s' for k,v in a.tags.items()]
            #st = ', '.join(tags)
            #st = repr(dir(a))
            printf("%s - vm=%s domain=%s", a.get('PublicIp'), a.get('InstanceId', '-'), a.get('Domain', '-'))

    def cmd_show_ebs(self):
        """Show EBS volumes.

        Group: info
        """
        client = self.get_ec2_client()
        res = client.describe_volumes()
        for v in res['Volumes']:
            a = v.get('Attachments')
            vm_id = '-'
            if a:
                vm_id = a[0].get('InstanceId')
            t = v.get('CreateTime').strftime('%Y-%m-%d')
            print("%s@%s size=%dG stat=%s created=%s" % (v['VolumeId'], vm_id, v['Size'], v['State'], t))

    def cmd_show_tables(self):
        """Show DynamoDB tables.

        Group: dynamodb
        """
        ddb = self.get_ddb()
        for t in ddb.list_tables()['TableNames']:
            print(t)

    def cmd_describe_table(self, tblname):
        """Show details about DynamoDB table.

        Group: dynamodb
        """
        ddb = self.get_ddb()
        desc = ddb.describe_table(TableName=tblname)['Table']
        print_json(desc)

    def cmd_get_item(self, tbl_name, item_key):
        """Get item from DynamoDB table.

        Group: dynamodb
        """
        ddb = self.get_ddb()
        res = ddb.get_item(TableName=tbl_name, Key={'hash_key': {'S': item_key}})
        print_json(res)

    def get_stamp(self):
        commit_id = local_cmd(['git', 'rev-parse', 'HEAD'])
        commit_id = commit_id[:7]   # same length as git log --abbrev-commit
        return commit_id

    def load_tags(self, obj):
        tags = {}
        if obj and obj.get('Tags'):
            for tag in obj.get('Tags'):
                tags[tag['Key']] = tag['Value']
        return tags

    def set_stamp(self, vm_id, name, commit_id, *dirs):
        if name is None:
            return
        client = self.get_ec2_client()

        vm = self.vm_lookup(vm_id)
        old_tags = self.load_tags(vm)

        tags = [{'Key': name, 'Value': commit_id}]
        client.create_tags(Resources=[vm_id], Tags=tags)

        old_id = old_tags.get('Commit', '?')
        old_id = old_tags.get(name, old_id)
        if commit_id == old_id:
            printf("%s: %s - no new commits", name, vm_id)
        else:
            printf("%s: %s", name, vm_id)
            show_commits(old_id, commit_id, list(dirs), self.git_dir)

    def gen_user_data(self):
        rnd = secrets.token_urlsafe(20)
        mimedata = USERDATA.replace('RND', rnd)
        if "AUTHORIZED_USER_CREATION" in mimedata:
            mimedata = mimedata.replace(
                "AUTHORIZED_USER_CREATION", self.make_user_creation()
            )
        return gzip.compress(mimedata.encode("utf8"))

    def cmd_create(self):
        """Create instance.

        Group: vm
        """
        ids = self.vm_create_start()
        self.vm_create_finish(ids)
        return ids

    def get_disk_map(self):
        """Parse disk_map option.
        """
        disk_map = self.cf.getdict("disk_map", {})
        if not disk_map:
            disk_map = {"root": "size=12"}

        res_map = {}
        for dev in disk_map:
            val = disk_map[dev]
            local = {}
            for opt in val.split(":"):
                if "=" in opt:
                    k, v = opt.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                else:
                    k = v = opt.strip()
                    if not k:
                        continue
                    if k.startswith("ephemeral"):
                        k = "ephemeral"
                if k in ("size", "count"):
                    v = int(v)
                local[k] = v
            if "count" not in local:
                local["count"] = 1
            if "size" not in local:
                raise UsageError("Each element in disk_map needs size")
            res_map[dev] = local

        # sanity check if requested
        disk_require_order = self.cf.getlist("disk_require_order", [])
        if disk_require_order:
            # order from disk_map
            got_order = sorted([
                (res_map[name]["size"], res_map[name]["count"], name)
                for name in res_map
            ])
            names_order = [f"{name}:{count}" for size, count, name in got_order]

            # order from disk_require_order
            counted_order = [
                key if ":" in key else key + ":1"
                for key in disk_require_order
            ]

            if names_order != counted_order:
                raise UsageError("Order mismatch:\n  require=%r\n  got=%r" % (counted_order, names_order))

        return res_map

    def get_next_raw_device(self, base_dev, used):
        prefix = base_dev[:-1]
        last = ord(base_dev[-1])
        while chr(last) <= 'z':
            current_dev = '%s%c' % (prefix, last)
            if current_dev not in used:
                used.add(current_dev)
                return current_dev
            last += 1
        raise Exception('Failed to generate disk name: %r used=%r' % (base_dev, used))

    def vm_create_start(self):
        """Create instance.

        Group: vm
        """
        client = self.get_ec2_client()

        image_type = self.cf.get('image_type')
        image_id = self.cf.get(image_type + '_image_id', '')
        if image_id:
            image_name = ""
        else:
            image_name = self.cf.get('image_name')
            image_id = self.get_image_id(image_name)
            if not image_id:
                eprintf("ERROR: no image for name: %r" % image_name)
                sys.exit(1)

        key_name = self.cf.get('key_name')
        vm_type = self.cf.get('vm_type')
        sg_list = self.cf.getlist('security_groups')
        zone = self.cf.get('zone', '')
        cpu_credits = self.cf.get('cpu_credits', '')
        cpu_count = self.cf.getint('cpu_count', 0)
        cpu_thread_count = self.cf.getint('cpu_thread_count', 0)
        aws_extra_tags = self.cf.getdict('aws_extra_tags', {})
        xname = 'vm.' + self.env_name
        if self.role_name:
            xname += '.' + self.role_name
        if not zone:
            zone = None
        ebs_optimized = self.cf.getboolean('ebs_optimized', False)
        disk_type = self.cf.get('disk_type', 'gp2')

        disk_map = self.get_disk_map()
        if not disk_map:
            disk_map = {'root': {'size': 12}}

        # device name may be different for different AMIs
        res = client.describe_images(ImageIds=[image_id])
        if not res.get('Images'):
            eprintf("ERROR: no image: %r" % image_id)
            sys.exit(1)
        for img in res['Images']:
            root_device_name = img['RootDeviceName']

        devlog = []
        bdm = []
        ephemeral_idx = 0

        used_raw_devs = set()

        for dev in disk_map:
            bdev = {'DeviceName': dev}

            count = 1
            ebs = {}
            for k, v in disk_map[dev].items():
                if k == 'size':
                    ebs['VolumeSize'] = int(v)
                elif k == 'iops':
                    ebs['Iops'] = int(v)
                elif k == 'throughput':
                    ebs['Throughput'] = int(v)
                elif k == 'count':
                    count = int(v)
                elif k == 'type':
                    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
                    # Values: standard, gp2, io1, st1, sc1
                    ebs['VolumeType'] = v
                elif k == 'local':
                    bdev['VirtualName'] = v
                elif k == 'encrypted':
                    if v == 'encrypted':
                        v = '1'
                    ebs['Encrypted'] = bool(int(v))
                elif k in self.VOL_TYPES:
                    ebs['VolumeType'] = k
                elif k in self.VOL_ENC_TYPES:
                    ebs['VolumeType'] = k.split('-')[1]
                    ebs['Encrypted'] = True
                elif k == 'ephemeral':
                    bdev['VirtualName'] = v
                else:
                    eprintf("ERROR: unknown disk param: %r", k)
                    sys.exit(1)

            if bdev.get('VirtualName'):
                ebs.pop('VolumeSize', 0)
                if ebs:
                    eprintf("ERROR: ephemeral device cannot have EBS params: %r", ebs)
                    sys.exit(1)
            elif ebs:
                if 'VolumeSize' not in ebs:
                    ebs['VolumeSize'] = 10
                if 'VolumeType' not in ebs:
                    ebs['VolumeType'] = disk_type
                ebs['DeleteOnTermination'] = True

                bdev['Ebs'] = ebs

            for _ in range(count):
                bdev = bdev.copy()

                # fill DeviceName, mainly used for root selection, otherwise mostly useless
                if dev in ROOT_DEV_NAMES:
                    bdev['DeviceName'] = root_device_name
                    if root_device_name in ['/dev/sda1']:
                        used_raw_devs.add(root_device_name[:-1])
                    else:
                        used_raw_devs.add(root_device_name)
                elif ebs:
                    bdev['DeviceName'] = self.get_next_raw_device('/dev/sdf', used_raw_devs)
                else:
                    bdev['DeviceName'] = self.get_next_raw_device('/dev/sdb', used_raw_devs)

                if "VirtualName" in bdev:
                    bdev["VirtualName"] = "ephemeral%d" % (ephemeral_idx,)
                    ephemeral_idx += 1

                bdm.append(bdev)

                devlog.append('%s=%s' % (dev, bdev['DeviceName']))

        time_printf("AWS=%s Env=%s Role=%s Key=%s Image=%s(%s) AZ=%d",
                    self.cf.get('aws_main_account'),
                    self.env_name, self.role_name or '-', key_name,
                    image_name, image_id, self.availability_zone)

        time_printf("Creating VM, storage: %s" % ', '.join(devlog))

        # lookup subnet
        subnet_id = self.cf.get('subnet_id')

        # manual lookup for sgs
        sg_ids = self.sgroups_lookup(sg_list)
        if len(sg_list) != len(sg_ids):
            eprintf("ERROR: failed to resolve security groups: %r" % sg_list)
            sys.exit(1)

        instance_profile_arn = self.cf.get('instance_profile_arn', '')
        if not instance_profile_arn:
            instance_profile_arn = None

        instance_associate_public_ip = self.cf.getboolean('instance_associate_public_ip', False)

        user_data = self.gen_user_data()

        main_iface = {
            'DeviceIndex': 0,
            'Description': '%s' % self.full_role,
            'SubnetId': subnet_id,
            'AssociatePublicIpAddress': instance_associate_public_ip,
            'DeleteOnTermination': True,
            'Groups': sg_ids,
        }
        args = {
            'ImageId': image_id,
            'InstanceType': vm_type,
            'KeyName': key_name,
            'BlockDeviceMappings': bdm,
            'MinCount': 1,
            'MaxCount': 1,
            'NetworkInterfaces': [main_iface]
        }
        if zone:
            args['Placement'] = {'AvailabilityZone': zone}
        if instance_profile_arn:
            args['IamInstanceProfile'] = {'Arn': instance_profile_arn}
        if ebs_optimized:
            args['EbsOptimized'] = True
        if user_data:
            args['UserData'] = user_data
        if cpu_credits:
            # standard / unlimited (for t2.* instances)
            args['CreditSpecification'] = {'CpuCredits': cpu_credits}
        if cpu_count or cpu_thread_count:
            args['CpuOptions'] = {}
            if cpu_count:
                args['CpuOptions']['CoreCount'] = cpu_count
            if cpu_thread_count:
                args['CpuOptions']['ThreadsPerCore'] = cpu_thread_count

        # pre-fill tags
        self.new_commit = self.get_stamp()
        tags = [
            {'Key': 'Name', 'Value': xname},
            {'Key': 'Env', 'Value': self.env_name},
            {'Key': 'Commit', 'Value': self.new_commit},
            {'Key': 'Date', 'Value': time.strftime("%Y%m%d")},
        ]
        if self.role_name:
            tags.append({'Key': 'Role', 'Value': self.role_name})
        for k, v in aws_extra_tags.items():
            tags.append({'Key': k, 'Value': v})
        args['TagSpecifications'] = [
            {'ResourceType': 'instance', 'Tags': tags},
            {'ResourceType': 'volume', 'Tags': tags},
        ]

        # actual launch
        res = client.run_instances(**args)

        time.sleep(20)      # FIXME

        # collect ids
        ids = []
        for vm in res['Instances']:
            vm_id = vm['InstanceId']
            ids.append(vm_id)
        time_printf("Created: %s", ' '.join(ids))

        show_first = True
        while 1:
            ok = True
            vm_list = []
            for vm in self.ec2_iter_instances(InstanceIds=ids):
                if vm['State']['Name'] != 'running':
                    ok = False
                vm_list.append(vm)

            if show_first:
                self.show_vm_list(vm_list)
                show_first = False

            if ok:
                break
            else:
                time.sleep(5)
        time_printf("Instance is now starting up")

        return ids

    def vm_create_finish(self, ids):
        for vm_id in ids:
            self.new_ssh_key(vm_id)
        time_printf("Instances are ready")
        time.sleep(10)
        self._vm_map = {}
        return ids

    def cmd_create_primary(self):
        """Create primary VM.
        Group: vm
        """
        self.cf.set('vm_state', VmState.PRIMARY)

        primary_check_old = self.cf.getboolean('primary_check_old', False)
        primary_stop_old = self.cf.getboolean('primary_stop_old', False)

        if primary_check_old:
            running_vms = self.get_running_vms()
            if running_vms:
                raise UsageError('Env has running vms. Please stop them before create-primary.')

        start = time.time()
        self.modcmd_init(VmCmd.PREP)

        ids = self.cmd_create()

        first = None
        for vm_id in ids:
            if not first:
                first = vm_id
            self.do_prep(vm_id)

        # skip assign if tmux was used
        if self.options.tmux:
            printf("VM ID: %s", ", ".join(ids))
            printf("Skipping assign-vm, --tmux in use")
            return first

        self.assign_vm(first, primary_stop_old)

        end = time.time()
        printf("VM ID: %s", ", ".join(ids))
        printf("Total time: %s", fmt_dur(end - start))

        return first

    def cmd_create_secondary(self):
        """Create secondary vm.
        Group: vm
        """
        self.cf.set('vm_state', VmState.SECONDARY)
        start = time.time()

        self.modcmd_init(VmCmd.PREP)

        ids = self.cmd_create()
        first = None
        for vm_id in ids:
            if not first:
                first = vm_id
            self.do_prep(vm_id)

        end = time.time()
        printf("VM ID: %s", ", ".join(ids))
        printf("Total time: %d", int(end - start))

        #  reset vm state
        self.cf.set('vm_state', VmState.PRIMARY)
        return first

    def cmd_add_key(self, vm_id):
        """Extract SSH key from VM add EC2 tag.

        Group: vm
        """
        self.new_ssh_key(vm_id)

    def cmd_tag(self):
        """Set extra tags to vm and related volumes.

        Group: vm
        """
        if not self.env_name:
            raise Exception("No env_name")

        if not self.role_name:
            raise Exception("No role_name")

        tags = []
        aws_extra_tags = self.cf.getdict('aws_extra_tags', {})
        for k, v in aws_extra_tags.items():
            tags.append({'Key': k, 'Value': v})

        if tags:
            client = self.get_ec2_client()
            for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
                client.create_tags(Resources=[vm['InstanceId']], Tags=tags)
                for bdm in vm.get('BlockDeviceMappings', []):
                    ebs = bdm.get('Ebs')
                    if ebs:
                        client.create_tags(Resources=[ebs['VolumeId']], Tags=tags)

    def cmd_start(self, *ids):
        """Start instance.

        Group: vm
        """
        if ids:
            client = self.get_ec2_client()
            client.start_instances(InstanceIds=ids)

    def cmd_stop(self, *ids):
        """Stop instance.

        Group: vm
        """
        if ids:
            client = self.get_ec2_client()
            client.stop_instances(InstanceIds=ids)

    def cmd_terminate(self, *ids):
        """Terminate VM.

        Group: vm
        """
        if not ids:
            return
        client = self.get_ec2_client()

        stopped = set()
        for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
            if vm['State']['Name'] != 'stopped':
                continue
            if not self.options.all:
                if not self._check_tags(vm.get('Tags')):
                    continue
            stopped.add(str(vm['InstanceId']))

        bad = []
        for vm_id in ids:
            if vm_id not in stopped:
                bad.append(vm_id)

        if bad:
            raise UsageError("Instances not stopped: %s" % " ".join(bad))
        else:
            client.terminate_instances(InstanceIds=ids)

    def cmd_gc(self):
        """Terminate all stopped vms.

        Group: vm
        """
        gc_keep_count = self.cf.getint('gc_keep_count', 0)
        gc_keep_days = self.cf.getint('gc_keep_days', 0)
        s_max_time = None
        if gc_keep_days > 0:
            max_time = datetime.datetime.utcnow() - datetime.timedelta(days=gc_keep_days)
            s_max_time = max_time.isoformat()
        if gc_keep_days or gc_keep_count:
            print('gc: gc_keep_days: %d  gc_keep_count: %d  maxtime: %r' % (
                  gc_keep_days, gc_keep_count, s_max_time))

        client = self.get_ec2_client()
        garbage = []
        vms_iter = self.ec2_iter_instances(Filters=self.get_env_filters())
        vms_sorted = sorted(vms_iter, key=lambda vm: vm['LaunchTime'])
        keep_count = 0
        for vm in vms_sorted:
            if vm['State']['Name'] != 'stopped':
                continue
            if not self.options.all:
                if not self._check_tags(vm.get('Tags')):
                    continue
            vm_launchtime = vm['LaunchTime'].isoformat()
            if s_max_time and vm_launchtime >= s_max_time:
                keep_count += 1
                continue
            garbage.append(str(vm['InstanceId']))

        # remove some if necessary
        while garbage and gc_keep_count > keep_count:
            garbage.pop()
            keep_count += 1

        if garbage:
            printf("Terminating: %s", " ".join(garbage))
            client.terminate_instances(InstanceIds=garbage)
        elif keep_count > 0:
            printf("Keeping stopped instances")
        else:
            printf("No stopped instances")

    def cmd_ssh(self, *args):
        """SSH to VM and run command (optional).

        Group: admin
        """
        vm_ids, args = self.get_vm_args(args, allow_multi=True)
        for vm_id in vm_ids:
            if len(vm_ids) > 1:
                time_printf("Running on VM %s", vm_id)
            if len(args) == 1:
                self.vm_exec_tmux(vm_id, args[0], title="ssh")
            else:
                self.vm_exec_tmux(vm_id, args or [], title="ssh")

    def cmd_ssh_admin(self, *args):
        """SSH to VM and run command (optional).

        Group: admin
        """
        vm_ids, args = self.get_vm_args(args, allow_multi=True)
        for vm_id in vm_ids:
            if len(vm_ids) > 1:
                time_printf("Running on VM %s", vm_id)
            if len(args) == 1:
                self.vm_exec_tmux(vm_id, args[0], use_admin=True, title="ssh-admin")
            else:
                self.vm_exec_tmux(vm_id, args or [], use_admin=True, title="ssh-admin")

    def cmd_rsync(self, *args):
        """Use rsync to transport files.

        Group: admin
        """
        if len(args) < 2:
            raise UsageError("Need source and dest for rsync")
        self.vm_rsync(*args)

    def filter_key_lookup(self, predef, key, fname):
        if key in predef:
            return predef[key]

        if key == 'MASTER_KEYS':
            master_key_list = []
            nr = 1
            while 1:
                kname = "master_key_%d" % nr
                v = self.cf.get(kname, '')
                if not v:
                    break
                master_key_list.append("%s = %s" % (kname, v))
                nr += 1
            if not master_key_list:
                raise Exception("No master keys found")
            master_key_conf = "\n".join(master_key_list)
            return master_key_conf

        if key == 'SYSRANDOM':
            blk = os.urandom(3*16)
            b64 = binascii.b2a_base64(blk).strip()
            return b64.decode('utf8')

        if key == 'AUTHORIZED_KEYS':
            auth_users = self.cf.getlist('ssh_authorized_users', [])
            pat = self.cf.get('ssh_pubkey_pattern')
            keys = []
            for user in sorted(set(auth_users)):
                fn = os.path.join(self.keys_dir, pat.replace('USER', user))
                pubkey = open(fn, 'r').read().strip()
                keys.append(pubkey)
            return '\n'.join(keys)

        if key == 'AUTHORIZED_USER_CREATION':
            return self.make_user_creation()

        try:
            return self.cf.get(key)
        except NoOptionError:
            raise UsageError("%s: key not found: %s" % (fname, key))

    def make_user_creation(self):
        auth_groups = self.cf.getlist('authorized_user_groups', [])
        auth_users = self.cf.getlist('ssh_authorized_users', [])
        pat = self.cf.get('ssh_pubkey_pattern')
        script = []
        for user in sorted(set(auth_users)):
            fn = os.path.join(self.keys_dir, pat.replace('USER', user))
            pubkey = open(fn).read().strip()
            script.append(mk_sshuser_script(user, auth_groups, pubkey))
        return '\n'.join(script)

    def make_tar_filter(self, extra_defs=None):
        defs = {}
        if extra_defs:
            defs.update(extra_defs)
        tb = TarFilter(self.filter_key_lookup, defs)
        tb.set_live(self.is_live)
        return tb

    def conf_func_file(self, arg, sect, kname):
        """Returns contents of file, optionally gpg-decrypted.

        Usage: ${FILE ! filename}
        """
        if self.options.verbose:
            printf("FILE: %s", arg)
        fn = os.path.join(self.keys_dir, arg)
        if not os.path.isfile(fn):
            raise UsageError('%s - FILE missing: %s' % (kname, arg))
        if fn.endswith('.gpg'):
            return self.load_gpg_file(fn).rstrip('\n')
        return open(fn, 'r').read().rstrip('\n')

    def conf_func_key(self, arg, sect, kname):
        """Returns key from Terraform state file.

        Usage: ${KEY ! fn : key}
        """
        bfn, subkey = arg.split(':')
        if self.options.verbose:
            printf("KEY: %s : %s", bfn.strip(), subkey.strip())
        fn = os.path.join(self.keys_dir, bfn.strip())
        if not os.path.isfile(fn):
            raise UsageError('%s - KEY file missing: %s' % (kname, fn))
        cf = self.load_gpg_config(fn, 'vm-config')
        subkey = as_unicode(subkey.strip())
        try:
            return cf.get(subkey)
        except:
            raise UsageError("%s - Key '%s' unset in '%s'" % (kname, subkey, fn))

    def conf_func_tf(self, arg, sect, kname):
        """Returns key from Terraform state file.

        Usage: ${TF ! tfvar}
        """
        if ":" in arg:
            state_file, arg = [s.strip() for s in arg.split(":", 1)]
        else:
            state_file = self.cf.get('tf_state_file')
        val = tf_load_output_var(state_file, arg)

        # configparser expects strings
        if isinstance(val, str):
            # work around tf dots in route53 data
            val = val.strip().rstrip('.')
        elif isinstance(val, int):
            val = str(val)
        elif isinstance(val, float):
            val = repr(val)
        elif isinstance(val, bool):
            val = str(val).lower()
        else:
            raise UsageError("TF function got invalid type: %s - %s" % (kname, type(val)))
        return val

    def conf_func_members(self, arg, sect, kname):
        """Returns field that match patters.

        Usage: ${MEMBERS ! pat : fn : field}
        """
        pats, bfn, field = arg.split(':')
        fn = os.path.join(self.keys_dir, bfn.strip())
        if not os.path.isfile(fn):
            raise UsageError('%s - MEMBERS file missing: %s' % (kname, fn))

        idx = int(field, 10)

        findLabels = []
        for p in pats.split(','):
            p = p.strip()
            if p:
                findLabels.append(p)

        res = []
        for ln in open(fn):
            ln = ln.strip()
            if not ln or ln[0] == '#':
                continue
            got = False
            parts = ln.split(':')
            user = parts[0].strip()
            for label in parts[idx].split(','):
                label = label.strip()
                if label and label in findLabels:
                    got = True
                    break
            if got and user not in res:
                res.append(user)

        return ', '.join(res)

    def conf_func_tfaz(self, arg, sect, kname):
        """Returns key from Terraform state file.

        Usage: ${TFAZ ! tfvar}
        """
        if self.options.verbose:
            printf("TFAZ: %s", arg)
        if ":" in arg:
            state_file, arg = [s.strip() for s in arg.split(":", 1)]
        else:
            state_file = self.cf.get('tf_state_file')
        val = tf_load_output_var(state_file, arg)
        if not isinstance(val, list):
            raise UsageError("TFAZ function expects list param: %s" % kname)
        if self.availability_zone < 0 or self.availability_zone >= len(val):
            raise UsageError("AZ value out of range")
        return val[self.availability_zone]

    def conf_func_primary_vm(self, arg, sect, kname):
        """Lookup primary vm.

        Usage: ${PRIMARY_VM ! ${other_role}}
        """
        vm = self.get_primary_for_role(arg)
        return vm['InstanceId']

    def conf_func_network(self, arg, sect, kname):
        """Extract network address from CIDR.
        """
        return str(ipaddress.ip_network(arg).network_address)

    def conf_func_netmask(self, arg, sect, kname):
        """Extract 32-bit netmask from CIDR.
        """
        return str(ipaddress.ip_network(arg).netmask)

    def do_prep(self, vm_id: str):
        """Run initialized 'prep' command.
        """
        # pause for a moment
        time.sleep(15)

        cmd = VmCmd.PREP
        self.modcmd_run(cmd, [vm_id])

    def load_vm_file(self, vm_id, fn):
        load_cmd = ["sudo", "-nH", "cat", fn]
        return self.vm_exec(vm_id, load_cmd, get_output=True)

    def load_secondary_vars(self, primary_id):
        vmap = self.cf.getdict('load_secondary_files', {})
        for vname, primary_file in vmap.items():
            eprintf("Loading %s:%s", primary_id, primary_file)
            data = self.load_vm_file(primary_id, primary_file)
            self.cf.set(vname, as_unicode(data))

    _PREP_TGZ_CACHE = {}    # cmd->tgz
    _PREP_STAMP_CACHE = {}  # cmd->stamp

    def cmd_mod_test(self, cmd_name):
        """Test if payload can be created for command.

        Group: internal
        """
        self.modcmd_init(cmd_name)
        data = self._PREP_TGZ_CACHE[cmd_name]
        print("Data size: %d bytes" % len(data))
        return data

    def cmd_mod_dump(self, cmd_name):
        """Write tarball of command payload.

        Group: internal
        """
        self.modcmd_init(cmd_name)
        data = self._PREP_TGZ_CACHE[cmd_name]
        fn = 'data.tgz'
        open(fn, 'wb').write(data)
        print("%s: %d bytes" % (fn, len(data)))

    def cmd_mod_show(self, cmd_name):
        """Show vmlibs used for command.

        Group: internal
        """
        cwd = self.git_dir
        os.chdir(cwd)

        cmd_cf = self.cf.view_section('cmd.%s' % cmd_name)

        vmlibs = cmd_cf.getlist('vmlibs')

        print("Included libs")
        got = set()
        for mod in vmlibs:
            if mod not in got:
                print("+ " + mod)
                got.add(mod)

        exc_libs = []
        for mod in xglob('vmlib/**/setup.sh'):
            mod = '/'.join(mod.split('/')[1:-1])
            if mod not in got:
                exc_libs.append(mod)
        exc_libs.sort()

        print("Excluded libs")
        for mod in exc_libs:
            print("- " + mod)

    def has_modcmd(self, cmd_name: VmCmd):
        """Return true if command is configured from config.
        """
        return self.cf.has_section('cmd.%s' % cmd_name)

    def modcmd_init(self, cmd_name: VmCmd):
        """Run init script for command.
        """
        cmd_cf = self.cf.view_section('cmd.%s' % cmd_name)
        init_script = cmd_cf.get('init', '')
        if init_script:
            # let subprocess see current env
            subenv = os.environ.copy()
            subenv['VMTOOL_ENV_NAME'] = self.full_role
            run_successfully([init_script], cwd=self.git_dir, shell=True, env=subenv)

        self.modcmd_prepare(cmd_name)

    def modcmd_prepare(self, cmd_name: VmCmd):
        """Prepare data package for command.
        """
        cmd_cf = self.cf.view_section('cmd.%s' % cmd_name)
        stamp_dirs = cmd_cf.getlist('stamp_dirs', [])
        cmd_abbr = cmd_cf.get('command_tag', '')
        globs = cmd_cf.getlist('files', [])
        use_admin = cmd_cf.getboolean('use_admin', False)

        self._PREP_TGZ_CACHE[cmd_name] = b''
        self.modcmd_build_tgz(cmd_name, globs, cmd_cf)

        self._PREP_STAMP_CACHE[cmd_name] = {
            'cmd_abbr': cmd_abbr,
            'stamp_dirs': stamp_dirs,
            'stamp': self.get_stamp(),
            'use_admin': use_admin,
        }

    def modcmd_run(self, cmd_name, vm_ids):
        """Send mod data to server and run it.
        """
        info = self._PREP_STAMP_CACHE[cmd_name]
        data_info = 0
        for vm_id in vm_ids:
            data = self._PREP_TGZ_CACHE[cmd_name]
            if not data_info:
                data_info = 1
            print('RUNNING...')
            self.run_mod_data(data, vm_id, use_admin=info['use_admin'], title=cmd_name)
            if info['cmd_abbr']:
                self.set_stamp(vm_id, info['cmd_abbr'], info['stamp'], *info['stamp_dirs'])

    def process_pkgs(self):
        """Merge per-pkg variables into main config.

        Converts:

            [pkg.foo]
            pkg_pyinstall_vmlibs = a, b
            [pkg.bar]
            pkg_pyinstall_vmlibs = c, d

        To:
            [vm-config]
            pkg_pyinstall_vmlibs = a, b, c, d
        """
        cf = self.cf.cf
        vmap = {}
        for sect in cf.sections():
            if sect.startswith('pkg.'):
                for opt in cf.options(sect):
                    if opt not in vmap:
                        vmap[opt] = []
                    done = set(vmap[opt])
                    val = cf.get(sect, opt)
                    for v in val.split(','):
                        v = v.strip()
                        if v and (v not in done):
                            vmap[opt].append(v)
                            done.add(v)
        for k, v in vmap.items():
            cf.set('vm-config', k, ', '.join(v))

    # in use
    def modcmd_build_tgz(self, cmd_name, globs, cmd_cf=None):
        cwd = self.git_dir
        os.chdir(cwd)

        defs = {}
        mods_ok = True
        vmlibs = []
        cert_fns = set()
        if cmd_cf:
            vmlibs = cmd_cf.getlist('vmlibs', [])
        if vmlibs:
            done_vmlibs = []
            vmdir = 'vmlib'
            globs = list(globs)
            for mod in vmlibs:
                if mod in done_vmlibs:
                    continue
                if not mod:
                    continue
                mdir = os.path.join(vmdir, mod)
                if not os.path.isdir(mdir):
                    printf("Missing module: %s" % mdir)
                    mods_ok = False
                elif not os.path.isfile(mdir + '/setup.sh'):
                    printf("Broken module, no setup.sh: %s" % mdir)
                    mods_ok = False
                globs.append('vmlib/%s/**' % mod)
                done_vmlibs.append(mod)

                cert_ini = os.path.join(mdir, 'certs.ini')
                if os.path.isfile(cert_ini):
                    cert_fns.add(cert_ini)
            defs['vm_modules'] = '\n'.join(done_vmlibs) + '\n'
            globs.append('vmlib/runner.*')
            globs.append('vmlib/shared/**')
        if not mods_ok:
            sys.exit(1)

        dst = self.make_tar_filter(defs)

        for tmp in globs:
            subdir = '.'
            if isinstance(tmp, str):
                flist = xglob(tmp)
            else:
                subdir = tmp[1]
                if subdir and subdir != '.':
                    os.chdir(subdir)
                else:
                    subdir = '.'
                flist = xglob(tmp[0])
                if len(tmp) > 2:
                    exlist = tmp[2:]
                    flist2 = []
                    for fn in flist:
                        skip = False
                        for ex in exlist:
                            if fnmatch(fn, ex):
                                skip = True
                                break
                        if not skip:
                            flist2.append(fn)
                    flist = iter(flist2)
                if subdir:
                    os.chdir(cwd)

            for fn in flist:
                real_fn = os.path.join(subdir, fn)
                if os.path.isdir(real_fn):
                    #dst.add_dir(item.path, stat.S_IRWXU, item.mtime)
                    pass
                else:
                    with open(real_fn, 'rb') as f:
                        st = os.fstat(f.fileno())
                        data = f.read()
                        dst.add_file_data(fn, data, st.st_mode & stat.S_IRWXU, st.st_mtime)

        # pass parameters to cert.ini files
        defs = {'env_name': self.env_name}
        if self.role_name:
            defs['role_name'] = self.role_name
        if self.cf.has_section('ca-config'):
            items = self.cf.view_section('ca-config').items()
            defs.update(items)

        # create keys & certs
        for cert_ini in cert_fns:
            printf("Processing certs: %s", cert_ini)
            mdir = os.path.dirname(cert_ini)
            keys = load_cert_config(cert_ini, self.load_ca_keypair, defs)
            for kname in keys:
                key, cert, _ = keys[kname]
                key_fn = '%s/%s.key' % (mdir, kname)
                cert_fn = '%s/%s.crt' % (mdir, kname)
                dst.add_file_data(key_fn, key, 0o600)
                dst.add_file_data(cert_fn, cert, 0o600)

        # finish
        dst.close()
        tgz = dst.getvalue()
        self._PREP_TGZ_CACHE[cmd_name] = tgz
        time_printf("%s: tgz bytes: %s", cmd_name, len(tgz))

    def load_ca_keypair(self, ca_name):
        intca_dir = self.cf.get(ca_name + '_dir', '')
        if not intca_dir:
            intca_dir = self.cf.get('intca_dir')
        pat = '%s/%s/%s_*.key.gpg' % (self.keys_dir, intca_dir, ca_name)
        res = list(sorted(xglob(pat)))
        if not res:
            raise UsageError("CA not found: %s - %s" % (ca_name, intca_dir))
        #names = [fn.split('/')[-1] for fn in res]
        idx = 0   # -1
        last_key = res[idx]
        #printf("CA: using %s from [%s]", names[idx], ', '.join(names))
        last_crt = last_key.replace('.key.gpg', '.crt')
        if not os.path.isfile(last_crt):
            raise UsageError("CA cert not found: %s" % last_crt)
        if not os.path.isfile(last_key):
            raise UsageError("CA key not found: %s" % last_key)
        return (last_key, last_crt)

    def run_mod_data(self, data, vm_id, use_admin=False, title=None):

        tmp_uuid = str(uuid.uuid4())
        run_user = 'root'

        launcher = './tmp/%s/vmlib/runner.sh "%s"' % (tmp_uuid, vm_id)
        rm_cmd = 'rm -rf'
        if run_user:
            launcher = 'sudo -nH -u %s %s' % (run_user, launcher)
            rm_cmd = 'sudo -nH ' + rm_cmd

        time_printf("%s: Sending data - %d bytes", vm_id, len(data))
        decomp_script = 'install -d -m 711 tmp && mkdir -p "tmp/%s" && tar xzf - --warning=no-timestamp -C "tmp/%s"' % (
            tmp_uuid, tmp_uuid
        )
        self.vm_exec(vm_id, ["/bin/sh", "-c", decomp_script, 'decomp'], data, use_admin=use_admin)

        time_printf("%s: Running", vm_id)
        cmdline = ["/bin/sh", "-c", launcher, 'runit']
        self.vm_exec_tmux(vm_id, cmdline, use_admin=use_admin, title=title)

    def cmd_tmux_attach(self, vm_id):
        """Attach to regular non-admin session.

        Group: vm
        """
        cmdline = shlex.split(self.cf.get('tmux_attach'))
        self.vm_exec(vm_id, cmdline, None, use_admin=False)

    def cmd_tmux_attach_admin(self, vm_id):
        """Attach to admin session.

        Group: vm
        """
        cmdline = shlex.split(self.cf.get('tmux_attach'))
        self.vm_exec(vm_id, cmdline, None, use_admin=True)

    def cmd_get_output(self, vm_id):
        """Print console output.

        Group: vm
        """
        client = self.get_ec2_client()
        res = client.get_console_output(InstanceId=vm_id)
        if res.get('Output'):
            # py3 still manages to organize codec=ascii errors
            f = os.fdopen(sys.stdout.fileno(), 'wb', buffering=0)
            v = res['Output'].encode('utf8', 'replace')
            f.write(v)

    def cmd_show_primary(self):
        """Show primary VM id.

        Group: internal
        """
        ids = self.get_primary_vms()
        print(ids[0])

    def cmd_assign_vm(self, vm_id):
        """Set another VM to serve primary IP.

        Group: vm
        """
        self.assign_vm(vm_id, False)

    def get_private_iface(self, vm_id):
        last_idx = None
        iface_id = None
        for vm in self.ec2_iter_instances(InstanceIds=[vm_id]):
            if vm['InstanceId'] != vm_id:
                continue
            for iface in vm['NetworkInterfaces']:
                cur_idx = iface['Attachment']['DeviceIndex']
                if last_idx is None or cur_idx < last_idx:
                    iface_id = iface['NetworkInterfaceId']
                    last_idx = iface['Attachment']['DeviceIndex']
        return iface_id

    def raw_assign_vm_private_ip(self, vm_id, private_ip):
        client = self.get_ec2_client()

        iface_id = self.get_private_iface(vm_id)
        res = client.assign_private_ip_addresses(
            NetworkInterfaceId=iface_id,
            PrivateIpAddresses=[private_ip],
            AllowReassignment=True)
        return res

    def raw_assign_vm(self, vm_id):
        """Actual assign().  Returns old vm_id.
        """
        res = res2 = res3 = res4 = None
        domain_eip = self.cf.get('domain_eip', '')
        if domain_eip:
            res = self.raw_assign_vm_eip(vm_id, domain_eip)

        assign_private_ip = self.cf.get('assign_private_ip', '')
        if assign_private_ip:
            res4 = self.raw_assign_vm_private_ip(vm_id, assign_private_ip)

        public_dns_zone_id = self.cf.get('public_dns_zone_id', '')
        zone_id = self.cf.get('internal_dns_zone_id', '')
        if zone_id or public_dns_zone_id:
            self.cmd_assign_dns(vm_id)

        internal_eni = self.cf.get('internal_eni', '')
        if internal_eni:
            self.cmd_assign_eni(vm_id)

        return res or res4

    def cmd_assign_eni(self, vm_id):
        """Assign Elastic Network Interface to VM.

        Group: vm
        """
        internal_eni = self.cf.get('internal_eni')

        client = self.get_ec2_client()

        res = client.describe_network_interfaces(NetworkInterfaceIds=[internal_eni])
        for iface in res['NetworkInterfaces']:
            att = iface.get('Attachment')
            if att and att.get('InstanceId'):
                att_id = att['AttachmentId']
                old_vm_id = att['InstanceId']

                printf('detaching %s from %s', att_id, old_vm_id)
                client.detach_network_interface(AttachmentId=att_id, Force=True)

                printf("waiting until ENI is detached")
                while True:
                    time.sleep(5)
                    wres = client.describe_network_interfaces(NetworkInterfaceIds=[internal_eni])
                    if wres['NetworkInterfaces'][0]['Status'] == 'available':
                        break

        printf("attaching ENI")
        res = client.attach_network_interface(
            NetworkInterfaceId=internal_eni,
            InstanceId=vm_id,
            DeviceIndex=1)
        printf("Attached ENI: %s", internal_eni)

    def raw_assign_vm_eip(self, vm_id, ip):
        time_printf("Associating address %s with %s", ip, vm_id)
        client = self.get_ec2_client()

        alloc_id = None
        cur_vm_id = None
        res = client.describe_addresses()   # FIXME: filter early
        for a in res['Addresses']:
            if a.get('PublicIp') == ip:
                cur_vm_id = a.get('InstanceId')
                alloc_id = a.get('AllocationId')
                break

        subnet_id = self.cf.get('subnet_id')
        args = dict(InstanceId=vm_id)
        args['AllocationId'] = alloc_id
        args['AllowReassociation'] = True
        client.associate_address(**args)
        self.wait_switch(vm_id, ip)
        time.sleep(10)
        time_printf("IP switch done")

        self._vm_map = {}

        return cur_vm_id

    def assign_vm(self, vm_id, stop_old_vm=False):
        """Set another VM to serve primary IP.
        """
        cur_vm_id = self.raw_assign_vm(vm_id)

        client = self.get_ec2_client()
        if cur_vm_id and vm_id != cur_vm_id and stop_old_vm:
            time_printf("Stopping old VM: %s" % cur_vm_id)
            client.stop_instances(InstanceIds=[cur_vm_id])
        time_printf("IP switch done")

    def wait_switch(self, vm_id, ip, debug=False):
        printf("waiting for ip switch")
        while 1:
            time.sleep(10)
            vm = self.vm_lookup(vm_id, cache=False)
            if vm.get('PublicIpAddress') == ip:
                break

        # reset cache
        self._vm_map = {}

        printf("waiting until vm is online")
        while 1:
            time.sleep(10)

            # look if SSH works
            hdr = b''
            try:
                s = socket.create_connection((ip, 22), 10)
                hdr = s.recv(128)           # pylint:disable=no-member
                s.close()
                if debug:
                    print(repr(hdr))
                if hdr.find(b'OpenSSH') < 0:
                    continue
            except Exception as d:
                if debug:
                    print("connect failed: %s" % str(d))
                continue

            # check actual instance id
            if True:
                return
            cmd = ['wget', '-q', '-O-', 'http://169.254.169.254/latest/meta-data/instance-id']
            cur_id = self.vm_exec(vm_id, cmd, get_output=True, check_error=False)
            if cur_id == vm_id.encode('utf8'):
                return

    def cmd_test_wait(self):
        """Wait until VM becomes primary.

        Group: internal
        """
        ids = self.get_primary_vms()
        vm = self.vm_lookup(ids[0])
        self.wait_switch(vm['InstanceId'], vm['PublicIpAddress'], True)

    def cmd_failover(self, secondary_id, *old_primary_ids):
        """Takeover for dead primary.

        Group: vm
        """
        if self.options.tmux:
            raise UsageError('This command does not support tmux')

        self.change_cwd_adv()

        if old_primary_ids:
            # allow manual override
            primary_ids = old_primary_ids
        else:
            primary_ids = self.get_dead_primary()
            if len(primary_ids) > 1:
                raise UsageError('Dont know how to handle several primaries')
        primary_id = primary_ids[0]

        self.cf.set('primary_vm_id', primary_id)

        # make sure it exists
        self.vm_lookup(secondary_id)

        cmd = VmCmd.FAILOVER_PROMOTE_SECONDARY
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_run(cmd, [secondary_id])

        self.raw_assign_vm(secondary_id)

        return secondary_id

    def cmd_takeover(self, secondary_id):
        """Switch primary to another node.

        Group: vm
        """
        if self.options.tmux:
            raise UsageError('This command does not support tmux')

        self.change_cwd_adv()

        # make sure it exists
        self.vm_lookup(secondary_id)

        vm_ids = self.get_primary_vms()
        if not vm_ids:
            raise UsageError("No primary VM found")
        if len(vm_ids) > 1:
            raise UsageError("Too many primaries")

        # old primary
        primary_id = vm_ids[0]

        self.cf.set('primary_vm_id', primary_id)

        cmd = VmCmd.TAKEOVER_PREPARE_PRIMARY
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_run(cmd, [primary_id])

        cmd = VmCmd.TAKEOVER_PREPARE_SECONDARY
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_run(cmd, [secondary_id])

        cmd = VmCmd.TAKEOVER_FINISH_PRIMARY
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_run(cmd, [primary_id])

        cmd = VmCmd.TAKEOVER_FINISH_SECONDARY
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_run(cmd, [secondary_id])

        self.raw_assign_vm(secondary_id)
        return primary_id

    def cmd_full_upgrade(self):
        """Replace node, stop old one

        Group: vm
        """
        if self.options.tmux:
            raise UsageError('This command does not support tmux')
        old_primary = self.cmd_safe_upgrade()
        time.sleep(15)
        self.cmd_drop_node(old_primary)

    def cmd_safe_upgrade(self):
        """Keep node running and in cascade

        Group: vm
        """
        if self.options.tmux:
            raise UsageError('This command does not support tmux')

        vm_id = self.cmd_create_secondary()
        old_primary = self.cmd_takeover(vm_id)

        if self.new_commit and self.old_commit:
            show_commits(self.old_commit, self.new_commit, [], self.git_dir)

        return old_primary

    def cmd_drop_node(self, vm_id):
        """Drop database node from cascade.

        Group: vm
        """
        if self.options.tmux:
            raise UsageError('This command does not support tmux')

        printf("Drop node: %s", vm_id)

        cmd = VmCmd.DROP_NODE_PREPARE
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_run(cmd, [vm_id])

        self.cmd_stop(vm_id)

    def load_modcmd_args(self, args):
        vms = []
        for a in args:
            if a.startswith('i-'):
                vms.append(a)
            else:
                raise UsageError("command supports only vmid args")
        if vms:
            return vms
        return self.get_primary_vms()

    def work(self):
        cmd = self.options.command
        cmdargs = self.options.args
        if not cmd:
            raise UsageError("Need command")
        #eprintf('vmtool - env_name: %s  git_dir: %s', self.env_name, self.git_dir)
        cmd_section = 'cmd.%s' % cmd
        if self.cf.has_section(cmd_section):
            cf2 = self.cf.view_section(cmd_section)
            if cf2.get('vmlibs', ''):
                vms = self.load_modcmd_args(cmdargs)
                self.change_cwd_adv()
                self.modcmd_init(cmd)
                self.modcmd_run(cmd, vms)
            else:
                self.run_console_cmd(cmd, cmdargs)
        else:
            super(VmTool, self).work()

    def run_console_cmd(self, cmd, cmdargs):
        cmd_cf = self.cf.view_section('cmd.%s' % cmd)
        cmdline = cmd_cf.get('vmrun')
        argparam = cmd_cf.get('vmrun_arg_param', '')

        fullcmd = shlex.split(cmdline)
        vm_ids, args = self.get_vm_args(cmdargs, allow_multi=True)
        if args:
            if argparam:
                fullcmd = fullcmd + [argparam, ' '.join(args)]
            else:
                fullcmd = fullcmd + args

        if len(vm_ids) > 1 and self.options.tmux:
            raise UsageError("Cannot use tmux in parallel")

        for vm_id in vm_ids:
            if len(vm_ids) > 1:
                time_printf("Running on VM %s", vm_id)
            self.vm_exec_tmux(vm_id, fullcmd, title=cmd)

    def change_cwd_adv(self):
        # cd .. until there is .git
        if not self._change_cwd_gittop():
            os.chdir(self.git_dir)

    def _change_cwd_gittop(self):
        vmlib = 'vmlib/runner.sh'
        num = 0
        maxstep = 30
        pfx = '.'
        while True:
            if os.path.isdir(os.path.join(pfx, '.git')):
                if os.path.isfile(os.path.join(pfx, vmlib)):
                    os.chdir(pfx)
                    return True
                else:
                    break
            if num > maxstep:
                break
            pfx = os.path.join(pfx, '..')
            num += 1
        return False

    def get_image_id(self, image_name):
        client = self.get_ec2_client()
        res = client.describe_images(Owners=['self'], Filters=[{'Name': 'name', 'Values': [image_name]}])
        if res['Images']:
            return res['Images'][0]['ImageId']
        return None

    def cmd_build_image(self):
        """Create VM and build image from it.

        Group: image
        """
        if self.options.tmux:
            raise UsageError('This command does not support tmux')

        client = self.get_ec2_client()

        name = self.cf.get('image_name')
        desc = self.cf.get('image_desc')
        copy_regions = self.cf.getlist('image_copy_regions', [])
        time_printf("BuildImage: name=%s", name)

        image_id = self.get_image_id(name)
        if image_id:
            raise UsageError("Image with this name already exists")

        vm_id = self.cmd_create_primary()
        self.cmd_stop(vm_id)

        wait = True
        while wait:
            time.sleep(5)
            for vm in self.ec2_iter_instances(InstanceIds=[vm_id]):
                if vm['State']['Name'] == 'stopped':
                    wait = False

        time_printf("creating image")
        image_id = self.cmd_create_image(vm_id, name, desc)

        time_printf("waiting for image finish")
        wait = True
        while wait:
            time.sleep(15)
            res = client.describe_images(Owners=['self'], ImageIds=[image_id])
            for img in res['Images']:
                if img['State'] == 'available':
                    wait = False
        time_printf("done")

        for region in copy_regions:
            printf("Copying image to %s", region)
            rclient = self.get_ec2_client(region)
            res = rclient.copy_image(Name=name, SourceImageId=image_id, SourceRegion=self._region)
            printf("Image copied to %s as %s", region, res['ImageId'])

    def cmd_create_image(self, vm_id, name, desc):
        """Create image from existing VM.

        Group: image
        """
        client = self.get_ec2_client()
        res = client.create_image(InstanceId=vm_id, Name=name, Description=desc)
        image_id = res['ImageId']
        time_printf("Result image id: %s", image_id)
        return image_id

    def cmd_delete_image(self, image_id):
        """Remove image.

        Group: image
        """
        client = self.get_ec2_client()
        snap_id = None
        res = client.describe_images(Owners=['self'], ImageIds=[image_id])
        for img in res['Images']:
            for bdm in img['BlockDeviceMappings']:
                if bdm.get('Ebs'):
                    snap_id = bdm['Ebs']['SnapshotId']
        client.deregister_image(ImageId=image_id)
        client.delete_snapshot(SnapshotId=snap_id)

    def cmd_show_images(self):
        """Show images

        Group: image
        """
        client = self.get_ec2_client()
        res = client.describe_images(Owners=['self'])
        self.show_image_list(res['Images'], r'.*\D-')

    def show_image_list(self, image_list, grprx=None):
        """Walk over list, show only latest by group, unless --all given.
        """
        image_list = sorted(image_list, key=lambda img: img['CreationDate'])
        if grprx and not self.options.all:
            cache = {}
            for img in image_list:
                m = re.match(grprx, img['Name'])
                if m:
                    tag = m.group(0)
                    cache[tag] = img
            image_list = cache.values()
        for img in image_list:
            self.show_image(img)

    def show_image(self, img):
        """Details about single image.
        """
        printf("%s state=%s owner=%s alias=%s", img['ImageId'], img['State'], img['OwnerId'], img.get('ImageOwnerAlias', '-'))
        printf("  type=%s/%s/%s/%s/%s ctime=%s",
               img['VirtualizationType'], img['RootDeviceType'],
               img['Architecture'], img['Hypervisor'],
               img['Public'] and 'public' or 'private',
               img['CreationDate'])
        printf("  name=%s", img['Name'])
        if img.get('Description'):
            printf("  desc=%s", img.get('Description'))
        printf("  location=%s", img['ImageLocation'])
        if self.load_tags(img):
            printf("  tags=%s", self.load_tags(img))

        if not self.options.verbose:
            return
        printf("  disk_mapping:")
        for bdt in img['BlockDeviceMappings']:
            ebs = bdt.get('Ebs') or {}
            if ebs.get('SnapshotId'):
                printf("    %s: snapshot=%s size=%s",
                       bdt.get('DeviceName'), ebs.get('SnapshotId'), ebs.get('VolumeSize'))
            else:
                printf("    %s: ephemeral=%s",
                       bdt.get('DeviceName'), bdt.get('VirtualName'))

    def show_public_images(self, owner_id, namefilter, grprx):
        """Filtered request for public images.
        """
        client = self.get_ec2_client()
        res = client.describe_images(Owners=[owner_id], Filters=[
            {'Name': 'state', 'Values': ['available']},
            {'Name': 'is-public', 'Values': ['true']},
            {'Name': 'architecture', 'Values': ['x86_64']},         # x86_64 / i386 / arm
            {'Name': 'virtualization-type', 'Values': ['hvm']},     # paravirtual / hvm
            {'Name': 'root-device-type', 'Values': ['ebs']},        # ebs / instance-store
            {'Name': 'name', 'Values': [namefilter]},
        ])
        self.show_image_list(res['Images'], grprx)

    def cmd_show_image(self, *amis):
        """Show specific public images

        Group: image
        """
        for ami in amis:
            region = None
            if ':' in ami:
                region, ami = ami.split(":")
            client = self.get_ec2_client(region)
            res = client.describe_images(ImageIds=[ami])
            self.show_image_list(res['Images'])

    def cmd_show_images_debian(self, *codes):
        """Show Debian images

        Group: image
        """
        owner_id = '379101102735'   # https://wiki.debian.org/Cloud/AmazonEC2Image

        pat = 'debian-*'
        if codes:
            pat = 'debian-%s-*' % codes[0]
        self.show_public_images(owner_id, pat, r'debian-\w+-')

    def cmd_show_images_debian_new(self, *codes):
        """Show Debian images

        Group: image
        """
        owner_id = '136693071363'   # https://wiki.debian.org/Cloud/AmazonEC2Image/Buster

        pat = 'debian-*'
        if codes:
            pat = 'debian-%s-*' % codes[0]
        self.show_public_images(owner_id, pat, r'debian-\w+-')

    def cmd_show_images_ubuntu(self, *codes):
        """Show Ubuntu images

        Group: image
        """
        owner_id = '099720109477'   # Owner of images from https://cloud-images.ubuntu.com/
        #owner_id = '679593333241'  # Marketplace user 'Canonical Group Limited'

        pat = 'ubuntu/images/*'
        if codes:
            pat += '/ubuntu-%s-*' % codes[0]
        self.show_public_images(owner_id, pat, r'.*/ubuntu-\w+-')


    def cmd_show_images_ubuntu_minimal(self, *codes):
        """Show Ubuntu minimal images

        Group: image
        """
        owner_id = '099720109477'   # Owner of images from https://cloud-images.ubuntu.com/
        #owner_id = '679593333241'  # Marketplace user 'Canonical Group Limited'

        pat = 'ubuntu-minimal/images/*'
        if codes:
            pat += '/ubuntu-%s-*' % codes[0]
        self.show_public_images(owner_id, pat, r'.*/ubuntu-\w+-')

    def cmd_show_zones(self):
        """Show DNS zones set up under Route53.

        Group: info
        """
        client = self.get_route53()
        res = client.list_hosted_zones()
        for zone in res['HostedZones']:
            printf('%s - privale=%s  desc=%s', zone['Name'],
                   zone['Config']['PrivateZone'], zone['Config']['Comment'])

    def cmd_show_zone(self):
        """Show records under one DNS zone.

        Group: info
        """
        zone_id = self.cf.get('internal_dns_zone_id')
        for rres in self.route53_iter_rrsets(HostedZoneId=zone_id):
            printf('%s %s', rres['Name'], rres['Type'])
            for vrec in rres['ResourceRecords']:
                printf('    %s', vrec['Value'])

    def cmd_assign_dns(self, vm_id):
        """Assign DNS entries to VM.

        Group: vm
        """
        zone_id = self.cf.get('internal_dns_zone_id')
        rev_zone_id = self.cf.get('internal_arpa_zone_id', '')
        zone_name = self.cf.get('internal_dns_zone_name')
        local_name = self.cf.get('internal_dns_vm_name')
        public_dns_zone_id = self.cf.get('public_dns_zone_id', '')
        public_dns_full_name = self.cf.get('public_dns_full_name', '')
        public_dns_ttl = self.cf.get('public_dns_ttl', '60')

        vm = self.vm_lookup(vm_id)
        internal_ip = vm['PrivateIpAddress']
        public_ip = vm.get('PublicIpAddress')

        # internal dns
        int_full_name = '%s.%s' % (local_name, zone_name)
        if not int_full_name.endswith('.'):
            int_full_name = int_full_name + '.'

        changes = [
            {'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': int_full_name,
                    'Type': 'A',
                    'TTL': int(public_dns_ttl),
                    'ResourceRecords': [{'Value': internal_ip}]}}]
        batch = {'Comment': 'assign-dns', 'Changes': changes}
        time_printf("Assigning internal dns: %s -> %s", int_full_name, internal_ip)
        client = self.get_route53()
        res = client.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=batch)
        if res['ResponseMetadata']['HTTPStatusCode'] != 200:
            eprintf('failed to set internal dns: %r', res)
            sys.exit(1)

        # internal reverse dns
        if rev_zone_id:
            rev_name = '.'.join(reversed(internal_ip.split('.'))) + '.in-addr.arpa'
            changes = [
                {'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': rev_name, 'Type': 'PTR', 'TTL': 60,
                        'ResourceRecords': [{'Value': int_full_name}]}}]
            batch = {'Comment': 'assign-rdns', 'Changes': changes}
            time_printf("Assigning reverse dns: %s -> %s", rev_name, int_full_name)
            res = client.change_resource_record_sets(HostedZoneId=rev_zone_id, ChangeBatch=batch)
            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                eprintf('failed to set reverse dns: %r', res)
                sys.exit(1)

        # public dns
        if public_dns_full_name:
            if not public_ip:
                eprintf('request for public dns but vm does not have public ip: %r', vm_id)
                sys.exit(1)
            changes = [{'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': public_dns_full_name, 'Type': 'A', 'TTL': 60,
                            'ResourceRecords': [{'Value': public_ip}]}}]
            batch = {'Comment': 'assign-dns', 'Changes': changes}
            time_printf("Assigning public dns: %s -> %s", public_dns_full_name, public_ip)
            res = client.change_resource_record_sets(HostedZoneId=public_dns_zone_id, ChangeBatch=batch)
            if res['ResponseMetadata']['HTTPStatusCode'] != 200:
                eprintf('failed to set public dns: %r', res)
                sys.exit(1)

            # wait until locally seen
            time.sleep(45)
            while True:
                ip = socket.gethostbyname(public_dns_full_name)
                if ip == public_ip:
                    time_printf("Resolved public dns: %s -> %s", public_dns_full_name, public_ip)
                    break
                time.sleep(20)

    def cmd_clean_dns(self):
        """Clean unused DNS entries.

        Group: vm
        """
        zone_id = self.cf.get('internal_dns_zone_id')
        rev_zone_id = self.cf.get('internal_arpa_zone_id', '')

        internal_subnet_cidr = self.cf.get('internal_subnet_cidr')
        net = ipaddress.IPv4Network(as_unicode(internal_subnet_cidr))

        used_ips = set()

        for rec in self.route53_iter_rrsets(HostedZoneId=zone_id):
            if rec['Type'] != 'A':
                continue
            for vrec in rec['ResourceRecords']:
                ip = vrec['Value']
                addr = ipaddress.IPv4Address(as_unicode(ip))
                if addr in net:
                    used_ips.add(ip)

        for rec in self.route53_iter_rrsets(HostedZoneId=rev_zone_id):
            if rec['Type'] != 'PTR':
                continue
            name = rec['Name']
            if not name.endswith('.in-addr.arpa.'):
                print(repr(rec))
                continue
            name = name.replace('.in-addr.arpa.', '')
            ip = '.'.join(reversed(name.split('.')))
            addr = ipaddress.IPv4Address(as_unicode(ip))
            if addr in net:
                if ip in used_ips:
                    print("InUse: " + ip)
                else:
                    print("Old: " + ip)

    def get_internal_dns_ips(self):
        local_name = self.cf.get('internal_dns_vm_name', '')
        if not local_name:
            return []
        zone_id = self.cf.get('internal_dns_zone_id')
        zone_name = self.cf.get('internal_dns_zone_name')
        full_name = '%s.%s' % (local_name, zone_name)

        iplist = []
        for rec in self.route53_iter_rrsets(HostedZoneId=zone_id, StartRecordName=full_name):
            if rec['Type'] not in ('A', 'AAAA'):
                continue
            if not rec['Name'].startswith(full_name):
                continue
            for vrec in rec['ResourceRecords']:
                iplist.append(vrec['Value'])
        return iplist

    def get_dns_map(self, full=False):
        ipmap = {}
        #local_name = self.cf.get('internal_dns_vm_name', '')
        zone_id = self.cf.get('internal_dns_zone_id', '')
        if zone_id:
            for rec in self.route53_iter_rrsets(HostedZoneId=zone_id):
                if rec['Type'] not in ('A', 'AAAA'):
                    continue
                for vrec in rec['ResourceRecords']:
                    ipmap[vrec['Value']] = rec['Name']

        #pub_name = self.cf.get('public_dns_full_name', '')
        zone_id = self.cf.get('public_dns_zone_id', '')
        if zone_id:
            for rec in self.route53_iter_rrsets(HostedZoneId=zone_id):
                if rec['Type'] not in ('A', 'AAAA'):
                    continue
                for vrec in rec['ResourceRecords']:
                    ipmap[vrec['Value']] = rec['Name']

        # consider other zones
        for zone_id in self.cf.getlist('extra_internal_dns_zone_ids', []):
            for rec in self.route53_iter_rrsets(HostedZoneId=zone_id):
                if rec['Type'] not in ('A', 'AAAA'):
                    continue
                for vrec in rec['ResourceRecords']:
                    ipmap[vrec['Value']] = rec['Name']

        return ipmap

    def cmd_show_tf(self):
        """Show parameters from Terraform state.

        Group: config
        """
        state_file = self.cf.get('tf_state_file')
        tfvars = tf_load_all_vars(state_file)
        for k in sorted(tfvars.keys()):
            parts = k.split('.')
            if len(parts) <= 3 or self.options.all:
                printf("%s = %s", k, tfvars[k])

    def cmd_show_config(self, *args):
        """Show filled config for current VM.

        Group: config
        """
        desc = self.env_name
        if self.role_name:
            desc += '.' + self.role_name

        fail = 0
        for sect in sorted(self.cf.sections()):
            printf('[%s]', sect)
            for k in sorted(self.cf.cf.options(sect)):
                if args and k not in args:
                    continue
                try:
                    raw = self.cf.cf.get(sect, k, raw=True)
                    v = self.cf.cf.get(sect, k)
                    vs = v
                    if not self.options.verbose:
                        vs = vs.strip()
                        if vs.startswith('----') or vs.startswith('{'):
                            vs = vs.split('\n')[0]
                        else:
                            vs = re.sub(r'\n\s*', ' ', vs)
                        printf("%s = %s", k, vs)
                    else:
                        printf("%s = %s [%s] (%s)", k, vs, desc, raw)
                except Exception as ex:
                    fail = 1
                    eprintf("### ERROR ### key: '%s.%s' err: %s", sect, k, str(ex))
            printf('')
        if fail:
            sys.exit(fail)

    def cmd_show_config_raw(self, *args):
        """Show filled config for current VM.

        Group: config
        """
        self.cf.cf.write(sys.stdout)

    def cmd_check_config(self):
        """Check if config works.

        Group: config
        """
        fail = 0
        for k in self.cf.options():
            try:
                self.cf.getlist(k)
            except Exception as ex:
                fail = 1
                printf("key: '%s' err: %s", k, str(ex))
        if fail:
            printf("--problems--")
            sys.exit(fail)

    def cmd_test(self):
        """Test both config and initial payload for VM.

        Group: config
        """
        self.cmd_check_config()
        self.cmd_mod_test('prep')

    def cmd_test_files(self):
        """Show contents of prep command payload.

        Group: internal
        """
        data = self.cmd_mod_test('prep')
        rf = gzip.GzipFile(mode='rb', fileobj=io.BytesIO(data))
        tar = tarfile.TarFile(fileobj=rf)
        tar.list()

    def cmd_sts_decode(self, msg):
        """Decode payload from UnauthorizedOperation error.

        Group: internal
        """
        # req: sts:DecodeAuthorizationMessage
        client = self.get_boto3_client('sts')
        res = client.decode_authorization_message(EncodedMessage=msg)
        dec = res['DecodedMessage']
        data = json.loads(dec)
        print_json(data)

    #
    #  Gen client certs
    #

    def cmd_list_keys(self, path = ''):
        """List issued keys.

        Group: kms
        """
        for section_name in self.cf.sections():
            if not section_name.startswith('secrets'):
                continue
            secret_cf = self.cf.view_section(section_name)
            self._list_keys(secret_cf, path)

    def _list_keys(self, secret_cf, path):
        kind = secret_cf.get('kind')
        if path == 'ALL':
            pass
        elif path.startswith(kind):
            pass
        else:
            return

        cwd = self.git_dir
        os.chdir(cwd)
        certs_dir = secret_cf.get('certs_dir')
        certs_ini = os.path.join(certs_dir, 'certs.ini')
        if not os.path.isfile(certs_ini):
            raise ValueError('File not found: %s' % certs_ini)

        keys = load_cert_config(certs_ini, self.load_ca_keypair, {})
        client = self.get_boto3_client('secretsmanager')
        for kname, value in keys.items():
            if path == 'ALL':
                pass
            elif f'{kind}.{kname}'.startswith(path):
                pass
            else:
                continue
            _, _, cert_cf = value
            self._list_key(client, secret_cf, cert_cf)

    def _list_key(self, client, secret_cf, cert_cf):
        namespace = secret_cf.get('namespace')
        stage = secret_cf.get('stage')
        kind = secret_cf.get('kind')

        srvc_type = cert_cf['srvc_type']
        srvc_temp = cert_cf['srvc_temp']
        srvc_name = cert_cf['srvc_name']
        srvc_repo = cert_cf['srvc_repo']

        secret_name = f"{namespace}/{stage}/{kind}/{srvc_repo}/{srvc_type}/{srvc_temp}/{srvc_name}"
        try:
            r_description = client.describe_secret(SecretId = secret_name)
            r_value = client.get_secret_value(
                SecretId = secret_name)
            printf(secret_name)
            printf(pprint.pformat(r_description['Tags']))
            printf(pprint.pformat(json.loads(r_value['SecretString'])))
        except client.exceptions.ResourceNotFoundException:
            pass

    def cmd_upload_keys(self, path = ''):
        """Issue new certificates.

        Group: kms
        """
        for section_name in self.cf.sections():
            if not section_name.startswith('secrets'):
                continue
            secret_cf = self.cf.view_section(section_name)
            self._upload_certs(secret_cf, path)

    def _upload_certs(self, secret_cf, path):
        kind = secret_cf.get('kind')
        if path == 'ALL':
            pass
        elif path.startswith(kind):
            pass
        else:
            return

        cwd = self.git_dir
        os.chdir(cwd)
        certs_dir = secret_cf.get('certs_dir')
        certs_ini = os.path.join(certs_dir, 'certs.ini')
        if not os.path.isfile(certs_ini):
            raise ValueError('File not found')

        keys = load_cert_config(certs_ini, self.load_ca_keypair, {})
        client = self.get_boto3_client('secretsmanager')
        for kname, value in keys.items():
            if path == 'ALL':
                pass
            elif f'{kind}.{kname}'.startswith(path):
                pass
            else:
                continue

            key, cert, cert_cf = value
            self._upload_cert(client, secret_cf, kname, key, cert, cert_cf)

    def _upload_cert(self, client, secret_cf, kname, key, cert, cert_cf):
        namespace = secret_cf.get('namespace')
        stage = secret_cf.get('stage')
        kind = secret_cf.get('kind')

        srvc_type = cert_cf['srvc_type']
        srvc_temp = cert_cf['srvc_temp']
        srvc_name = cert_cf['srvc_name']
        srvc_repo = cert_cf['srvc_repo']

        db_name = cert_cf.get('db_name')
        db_user = cert_cf.get('db_user')

        ca_name = cert_cf.get('ca_name')

        root_cert = self._get_root_cert(cert_cf)

        secret_name = f"{namespace}/{stage}/{kind}/{srvc_repo}/{srvc_type}/{srvc_temp}/{srvc_name}"

        secret_data = {
            'key': key.decode('utf-8'),
            'crt': cert.decode('utf-8'),
        }
        if cert_cf['usage'] == 'client':
            secret_data['server_root_crt'] = root_cert.decode('utf-8')
        elif cert_cf['usage'] == 'server':
            secret_data['client_root_crt'] = root_cert.decode('utf-8')
        else:
            raise ValueError('Invalid value for usage: %s' % cert_cf['usage'])

        if db_name:
            secret_data['db_name'] = db_name
        if db_user:
            secret_data['db_user'] = db_user
        #if self.cf.has_option('%s_url' % ca_name):
        #    base_url = self.cf.get('%s_url' % ca_name)
        #    srvc_url = f"https://{kind}-{srvc_type}-{srvc_temp}.{base_url}"
        #    secret_data['url'] = srvc_url

        secret_str = json.dumps(secret_data)

        secret_tags = [
            {'Key': 'namespace', 'Value': namespace},
            {'Key': 'stage', 'Value': stage},
            {'Key': 'kind', 'Value': kind},
            {'Key': 'srvc_type', 'Value': srvc_type},
            {'Key': 'srvc_temp', 'Value': srvc_temp},
            {'Key': 'srvc_name', 'Value': srvc_name},
            {'Key': 'srvc_repo', 'Value': srvc_repo},
        ]

        sec_extra_tags = self.cf.getdict('sec_extra_tags', {})
        for k, v in sec_extra_tags.items():
            secret_tags.append({'Key': k, 'Value': v})

        try:
            client.describe_secret(SecretId = secret_name)
            is_existing_secret = True
        except client.exceptions.ResourceNotFoundException:
            is_existing_secret = False

        if is_existing_secret:
            response = client.update_secret(
                SecretId = secret_name,
                Description = secret_name,
                KmsKeyId = secret_cf.get('kms_key_id'),
                SecretString = secret_str)
            printf('Updated secret: %s' % secret_name)
        else:
            response = client.create_secret(
                Name = secret_name,
                Description = secret_name,
                KmsKeyId = secret_cf.get('kms_key_id'),
                SecretString = secret_str,
                Tags = secret_tags)
            printf('Created secret: %s' % secret_name)

    def _get_root_cert(self, cf):
        ca_dir = self.cf.get('%s_dir' % cf['ca_name'])
        if cf['usage'] == 'client':
            root_crt_fname = cf['server_root_crt']
        elif cf['usage'] == 'server':
            root_crt_fname = cf['client_root_crt']
        else:
            raise ValueError('Invalid value for usage: %s' % cf['usage'])

        root_crt = '%s/%s/%s' % (self.keys_dir, ca_dir, root_crt_fname)
        with open(root_crt, 'rb') as f:
            return f.read()

    def cmd_log_keys(self):
        """Copy issued certificates to log directory.

        Group: kms
        """
        cwd = self.ca_log_dir
        os.chdir(cwd)

        for section_name in self.cf.sections():
            if not section_name.startswith('secrets'):
                continue
            secret_cf = self.cf.view_section(section_name)
            self._log_keys(secret_cf)

    def _log_keys(self, secret_cf):
        namespace = secret_cf.get('namespace')
        stage = secret_cf.get('stage')
        kind = secret_cf.get('kind')

        client = self.get_boto3_client('secretsmanager')
        list_secrets_pager = self.pager(client, "list_secrets", "SecretList")
        for secret in list_secrets_pager():
            if not secret['Name'].startswith(f'{namespace}/{stage}/{kind}'):
                continue
            name = secret['Name']
            tags = secret['Tags']
            srvc_name = None
            for tag in tags:
                if tag['Key'] == 'srvc_name':
                    srvc_name = tag['Value']
                    break

            if srvc_name is None:
                continue

            if not os.path.isdir(name):
                os.makedirs(name)

            r_value = client.get_secret_value(
                SecretId = name)

            timestamp = r_value['CreatedDate'].strftime("%Y%m%d-%H%M%S")

            crt = json.loads(r_value['SecretString'])['crt'].encode('utf-8')
            with open(f'{name}/{timestamp}.crt', 'wb') as f:
                f.write(crt)

    def cmd_tag_keys(self):
        """Tag issued certificates with extra tags.

        Group: kms
        """
        if not self.env_name:
            raise Exception("No env_name")

        tags = []
        sec_extra_tags = self.cf.getdict('sec_extra_tags', {})
        for k, v in sec_extra_tags.items():
            tags.append({'Key': k, 'Value': v})

        if tags:
            client = self.get_boto3_client('secretsmanager')
            pager = self.pager(client, "list_secrets", "SecretList")
            for secret in pager():
                if secret['Name'].startswith(f'dp/{self.env_name}/'):
                    client.tag_resource(SecretId=secret['Name'], Tags=tags)

    def fetch_disk_info(self, vm_ids):
        args = {}
        args['Filters'] = self.get_env_filters()
        if vm_ids:
            args['InstanceIds'] = vm_ids

        vm_list = []
        for vm in self.ec2_iter_instances(**args):
            vm_list.append(vm)
        if not vm_list:
            raise UsageError("Instance not found")

        # vol_id->vol
        vol_map = self.get_volume_map(vm_list)

        # load disks from config
        disk_map = self.get_disk_map()

        vm_disk_names_size_order = self.cf.getlist('vm_disk_names_size_order')

        final_list = []
        for vm in vm_list:
            if vm['State']['Name'] != 'running':
                continue
            final_info = {
                'vm': vm,
                'config_disk_map': disk_map,
                'volume_map': {}, # name -> volume
                'device_map': {}, # name -> DeviceName
            }

            # load disk from running vm
            root_vol_id = None
            cur_vol_list = []
            dev_map = {}        # vol_id->dev_name
            for bdev in vm.get('BlockDeviceMappings', []):
                ebs = bdev.get('Ebs')
                if not ebs:
                    continue

                vol = vol_map[ebs['VolumeId']]
                vol_info = (vol['Size'], ebs['VolumeId'])
                dev_name = bdev.get('DeviceName')
                dev_map[ebs['VolumeId']] = dev_name
                if dev_name in ROOT_DEV_NAMES:
                    root_vol_id = ebs['VolumeId']
                    final_info['volume_map']['root'] = vol
                    final_info['device_map']['root'] = dev_name
                else:
                    cur_vol_list.append(vol_info)

            if not root_vol_id:
                raise UsageError("Root volume not found")

            # insert local disks
            ephemeral_nr = 0
            for disk_name, disk_conf in disk_map.items():
                eph_name = disk_conf.get('ephemeral')
                if not eph_name:
                    continue
                for nr in range(disk_conf["count"]):
                    # ignore eph_name, too messy
                    eph_id = f"ephemeral{ephemeral_nr}"
                    ephemeral_nr += 1
                    vol_map[eph_id] = {"Size": disk_conf["size"], "VolumeId": eph_id, "State": eph_name}
                    dev_map[eph_id] = f"/dev/{eph_id}"
                    vol_info = (disk_conf["size"], eph_id)
                    cur_vol_list.append(vol_info)

            # check if data is sane
            if len(cur_vol_list) != len(vm_disk_names_size_order):
                raise UsageError("Number of disks does not match:\n  cur=%r\n  names=%r" % (
                    cur_vol_list, vm_disk_names_size_order))

            cur_vol_list.sort()
            for nr, (size, vol_id) in enumerate(cur_vol_list):
                vol_name = vm_disk_names_size_order[nr]
                final_info['volume_map'][vol_name] = vol_map[vol_id]
                final_info['device_map'][vol_name] = dev_map[vol_id]
            final_list.append(final_info)

        return final_list

    def lookup_disk_config(self, vm_disk_info, vol_name):
        if vol_name.split('.')[-1].isdigit():
            xvol_name = '.'.join(vol_name.split('.')[:-1])
            vol_conf = vm_disk_info['config_disk_map'][xvol_name]
        else:
            vol_conf = vm_disk_info['config_disk_map'][vol_name]
        return vol_conf

    def show_disk_info(self, vm_disk_info, vol_name):
        vm = vm_disk_info['vm']
        vol_info = vm_disk_info['volume_map'][vol_name]
        dev_name = vm_disk_info['device_map'][vol_name]
        vol_conf = self.lookup_disk_config(vm_disk_info, vol_name)

        cursize = vol_info['Size']
        newsize = vol_conf['size']

        print("{vm_id}/{vol_id}".format(vm_id=vm['InstanceId'], vol_id=vol_info['VolumeId']))

        flag = ""
        if newsize != cursize:
            flag = " !!!"
        print(f"  name: {vol_name},  device: {dev_name}")
        print(f"  cursize: {cursize},   newsize: {newsize}{flag}")

        # attachement state
        xlist = []
        for att in vol_info.get('Attachments', []):
            # State/Device/InstanceId/VolumeId/DeleteOnTermination
            xlist.append(att['State'])
        attinfo = ""
        if xlist:
            attinfo = " / " + ",".join(xlist)

        # state: 'creating'|'available'|'in-use'|'deleting'|'deleted'|'error',
        print(f"  state: {vol_info['State']}{attinfo}")

        if vol_info.get('Iops') or vol_info.get('Throughput'):
            iops = vol_info.get('Iops', '-')
            throughput = vol_info.get('Throughput', '-')
            print(f"  iops: {iops}, throughput: {throughput}")

    def cmd_show_disks(self, *vm_ids):
        """Show detailed volume info.

        Group: info
        """
        vm_disk_list = self.fetch_disk_info(vm_ids)

        last_vm_id = None
        for vm_disk_info in vm_disk_list:
            if last_vm_id and last_vm_id != vm_disk_info['vm']['InstanceId']:
                print("")
            last_vm_id = vm_disk_info['vm']['InstanceId']

            for vol_name in vm_disk_info['volume_map']:
                self.show_disk_info(vm_disk_info, vol_name)

    def cmd_modify_disks(self, vm_id):
        """Increase disk size

        Group: admin
        """
        vm_disk_list = self.fetch_disk_info([vm_id])
        client = self.get_ec2_client()
        modified_vol_ids = []
        for vm_info in vm_disk_list:
            volume_map = vm_info['volume_map']
            for vol_name in volume_map:
                vol_info = volume_map[vol_name]
                vol_conf = self.lookup_disk_config(vm_info, vol_name)
                cursize = vol_info['Size']
                newsize = vol_conf['size']
                if cursize > newsize:
                    eprintf("WARNING: cannot decrease size: vol_name=%s old=%r new=%r", vol_name, cursize, newsize)
                    continue
                if cursize == newsize:
                    continue

                self.show_disk_info(vm_info, vol_name)

                # request size increase
                printf("Modifying %s, newsize=%d...", vol_info['VolumeId'], newsize)
                client.modify_volume(
                    VolumeId=vol_info['VolumeId'],
                    Size=newsize,
                )
                printf("Done")
                modified_vol_ids.append(vol_info['VolumeId'])

        iter_vol_modifications = self.pager(
            client, 'describe_volumes_modifications', 'VolumesModifications'
        )

        # wait until complete
        while modified_vol_ids:
            incomplete = 0
            for mod in iter_vol_modifications(VolumeIds=modified_vol_ids):
                mstate = mod.get('ModificationState')
                if not mstate:
                    continue
                if mstate not in (
                    'completed', 'failed',
                    # takes very long time but the volume is immediately usable
                    'optimizing',
                ):
                    incomplete += 1
                msg = ''
                if mod.get("StatusMessage"):
                    msg = "  msg={StatusMessage}".format(**mod)
                printf(
                    "{VolumeId}: state={ModificationState}"
                    " oldsize={OriginalSize} newsize={TargetSize}"
                    " progress={Progress}%{msg}".format(msg=msg, **mod))

            if not incomplete:
                break
            printf('')
            time.sleep(2)

        time_printf("Finished")

