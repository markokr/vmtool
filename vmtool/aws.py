"""AWS backend for vmtool.
"""

import sys
import os
import os.path
import subprocess
import time
import logging
import socket
import io
import tarfile
import uuid
import shlex
import re
import gzip
import json
import stat
import ipaddress
import datetime
import errno
import binascii
import argparse

from fnmatch import fnmatch

import boto3.session
import boto3.s3.transfer

from vmtool.util import ssh_add_known_host, parse_console, rsh_quote, as_unicode
from vmtool.util import printf, eprintf, time_printf, print_json, local_cmd, run_successfully
from vmtool.util import encode_base64, fmt_dur
from vmtool.xglob import xglob
from vmtool.tarfilter import TarFilter
from vmtool.scripting import EnvScript, UsageError
from vmtool.envconfig import load_env_config, find_gittop
from vmtool.config import Config, NoOptionError
from vmtool.terra import tf_load_output_var, tf_load_all_vars
from vmtool.certs import load_cert_config

# /usr/share/doc/cloud-init/userdata.txt
USERDATA = """\
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===BND==="

--===BND===
Content-Type: text/cloud-boothook; charset="us-ascii"
Content-Disposition: attachment; filename="early-init.sh"
Content-Transfer-Encoding: 7bit

#!/bin/sh
echo "$INSTANCE_ID: RND" > /dev/urandom
( ls -l --full-time /var/log; dmesg; ) | sha512sum > /dev/urandom
echo "$INSTANCE_ID: entropy added" > /dev/console

--===BND===--
"""

SSH_CONFIG = [
    '-o', 'ServerAliveInterval=60',
    '-o', 'HashKnownHosts=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'PreferredAuthentications=publickey',
]


def show_commits(old_id, new_id, dirs, cwd):
    cmd = ['git', '--no-pager', 'shortlog', '--no-merges', old_id + '..' + new_id]
    if dirs:
        cmd.append('--')
        cmd.extend(dirs)
    subprocess.call(cmd, cwd=cwd)

SSH_USER_CREATION = '''
adduser --gecos "{user}" --disabled-password {user} < /dev/null
install -d -o {user} -g {user} -m 700  ~{user}/.ssh
echo "{pubkey}" > ~{user}/.ssh/authorized_keys
chmod 600 ~{user}/.ssh/authorized_keys
chown {user}:{user} ~{user}/.ssh/authorized_keys

for grp in {auth_groups}; do
    adduser "{user}" "$grp"
done

'''

def mk_sshuser_script(user, auth_groups, pubkey):
    return SSH_USER_CREATION.format(user=user, auth_groups=' '.join(auth_groups), pubkey=pubkey)


class VmTool(EnvScript):
    __doc__ = __doc__

    _boto_sessions = None
    _boto_clients = None

    _vm_map = None

    role_name = None
    env_name = None     # name of current env
    full_role = None
    ssh_dir = None

    new_commit = None
    old_commit = None

    _price_data = None

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

        keys_dir = os.environ.get('VMTOOL_KEY_DIR',  os.path.join(self.git_dir, 'keys'))
        if not keys_dir or not os.path.isdir(keys_dir):
            raise UsageError('Set vmtool config dir: VMTOOL_KEY_DIR')

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

        self.keys_dir = keys_dir
        self.ssh_dir = ssh_dir

        self.cf = load_env_config(self.full_role, {
            'FILE': self.conf_func_file,
            'KEY': self.conf_func_key,
            'TF': self.conf_func_tf,
            'TFAZ': self.conf_func_tfaz,
        })
        self.process_pkgs()

        self._region = self.cf.get('region')
        self.ssh_known_hosts = os.path.join(self.ssh_dir, 'known_hosts')
        self.is_live = self.cf.getint('is_live', 0)

    def load_gpg_file(self, fn):
        if self.options.verbose:
            printf("GPG: %s", fn)
        # file data directly
        if not os.path.isfile(fn):
            raise UsageError("GPG file not found: %s" % fn)
        data = self.popen(['gpg', '-q', '-d', '--batch', fn])
        return as_unicode(data)

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
        p.add_argument("--running", action="store_true", help="Show only running instances")
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
        if not region:
            region = self._region
        if self._boto_clients is None:
            self._boto_clients = {}

        scode = (region, svc)
        if scode in self._boto_clients:
            client = self._boto_clients[scode]
        else:
            session = self.get_boto3_session(region)
            client = session.client(svc)
            self._boto_clients[scode] = client

        return client

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

    def pager(self, client, method, rname):
        """Create pager function for looping over long results.
        """
        lister = client.get_paginator(method)

        def pager(**kwargs):
            for page in lister.paginate(**kwargs):
                for rec in page[rname]:
                    yield rec
        return pager

    def ec2_iter_instances(self, **kwargs):
        client = self.get_ec2_client()
        pager = self.pager(client, 'describe_instances', 'Reservations')
        for rv in pager(**kwargs):
            for vm in rv['Instances']:
                yield vm

    def route53_iter_rrsets(self, **kwargs):
        client = self.get_route53()
        pager = self.pager(client, 'list_resource_record_sets', 'ResourceRecordSets')
        return pager(**kwargs)

    def vpc_lookup(self, vpc_name):
        client = self.get_ec2_client()
        res = client.describe_vpcs()
        for v in res['Vpcs']:
            if vpc_name == v['VpcId']:
                return v['VpcId']
            tags = self.load_tags(v)
            if tags.get('Name') == vpc_name:
                return v['VpcId']
        raise Exception("vpc not found: %r" % vpc_name)

    def sgroups_lookup(self, sgs_list):
        # manual lookup for sgs
        sg_ids = []
        names = []
        for sg in sgs_list:
            if sg.startswith('sg-'):
                sg_ids.append(sg)
            else:
                names.append(sg)
        if names:
            printf('DEPRECATED: sgroups_lookup: %r', names)
            client = self.get_ec2_client()
            res = client.describe_security_groups()
            for sg in res['SecurityGroups']:
                if sg.get('GroupName') in names:
                    sg_ids.append(sg['GroupId'])
                    names.remove(sg.get('GroupName'))
            if names:
                raise Exception("security groups not found: %r" % names)
        return sg_ids

    def show_vm_list(self, vm_list, adrmap=None, dnsmap=None):
        adrmap = adrmap or {}
        dnsmap = dnsmap or {}

        use_colors = sys.stdout.isatty()
        if use_colors:
            if sys.platform.startswith('win'):
                use_colors = False

        vm_list = sorted(vm_list, key=lambda vm: vm['LaunchTime'])

        vol_map = {}
        if self.options.verbose:
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

            int_ip = ''
            if vm.get('PrivateIpAddress'):
                int_ip = ' ip=%s' % vm['PrivateIpAddress']

            # one-line output
            printf("%s [%s%s%s]%s%s%s%s", vm['InstanceId'], c1, vm['State']['Name'], c2, name, tags, int_ip, eip)
            for xln in extra_lines:
                printf('  %s', xln)
            if not self.options.verbose:
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

        printf("get_volume_map: %r", vols)
        for vol in self.ec2_iter_volumes(VolumeIds=list(vols)):
            vmap[vol['VolumeId']] = vol
        return vmap

    def ec2_iter_volumes(self, **kwargs):
        client = self.get_ec2_client()
        pager = self.pager(client, 'describe_volumes', 'Volumes')
        for vol in pager(**kwargs):
            yield vol

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
        if use_admin:
            ssh_user = self.cf.get('ssh_admin_user')
        else:
            ssh_user = self.cf.get('user')

        ssh_debug = '-q'
        if self.options.verbose:
            ssh_debug = '-v'

        return ['ssh', ssh_debug, '-i', self.get_ssh_kfile(), '-l', ssh_user,
                '-o', 'UserKnownHostsFile=' + self.ssh_known_hosts] + SSH_CONFIG

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
        root_id = None
        nargs = []
        ids = []
        for a in args:
            t = a.split(':', 1)
            if len(t) == 1:
                nargs.append(a)
                continue
            if t[0]:
                vm_id = t[0]
            elif root_id:
                vm_id = root_id
            else:
                vm_id = root_id = self.get_primary_vms()[0]
            vm = self.vm_lookup(vm_id)
            self.put_known_host_from_tags(vm_id)
            a = "%s:%s" % (vm.get('PublicIpAddress'), t[1])
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
        for iface in vm['NetworkInterfaces']:
            assoc = iface.get('Association')
            if assoc:
                ip = assoc['PublicIp']
                dns = assoc['PublicDnsName']
                if ip:
                    iplist.append((ip, dns))
        ip = vm.get('PublicIpAddress')
        if ip and ip not in iplist:
            dns = vm.get('PublicDnsName')
            iplist.append((ip, dns))

        #public_dns_name = vm.get('PublicDnsName')

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
        for k, v in old_keys + new_keys:
            for ip, dns in iplist:
                ssh_add_known_host(self.ssh_known_hosts, dns, ip, k, v, vm_id)

    def get_env_filters(self):
        filters = []

        if self.options.running:
            filters.append({
                'Name': 'instance-state-name',
                'Values': ['running']
            })

        if not self.options.all:
            filters.append({
                'Name': 'tag:Env',
                'Values': [self.env_name],
            })
            if self.role_name:
                filters.append({
                    'Name': 'tag:Role',
                    'Values': [self.role_name],
                })
        return filters

    def get_running_vms(self):
        vmlist = []
        for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
            if not self._check_tags(vm.get('Tags'), True):
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

    def get_primary_vms(self):
        ec2 = self.get_ec2_client()

        if self.options.all_role_vms:
            return self.get_all_role_vms()

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
                eprintf("Primary VM for %s is %s", self.full_role, ','.join(main_vms))
                return main_vms
            raise UsageError("Primary VM not found")

        dnsmap = self.get_dns_map()
        for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
            if not self._check_tags(vm.get('Tags'), True):
                continue
            if vm['State']['Name'] != 'running':
                continue
            if vm.get('PrivateIpAddress') in dnsmap:
                main_vms.append(vm['InstanceId'])
            elif vm.get('PublicIpAddress') in dnsmap:
                main_vms.append(vm['InstanceId'])
        if not main_vms:
            raise UsageError("Primary VM not found")
        eprintf("Primary VM for %s is %s", self.full_role, ','.join(main_vms))
        return main_vms

    def get_all_role_vms(self):
        if not self.role_name:
            raise UsageError("Not in a role-based env")
        all_vms = []
        for vm in self.ec2_iter_instances(Filters=self.get_env_filters()):
            if not self._check_tags(vm.get('Tags'), True):
                continue
            if vm['State']['Name'] != 'running':
                continue
            all_vms.append(vm['InstanceId'])
        if not all_vms:
            raise UsageError("VMs not found")
        eprintf("Running VMs for %s: %s", self.full_role, ' '.join(all_vms))
        return all_vms

    def _check_tags(self, taglist, force_role=False):
        if not taglist:
            return False
        alt_env_name = self.cf.get('alt_env_name', '')
        gotenv = gotrole = False
        for tag in taglist:
            if tag['Key'] == 'Env':
                gotenv = True
                if tag['Value'] != self.env_name:
                    if not alt_env_name:
                        return False
                    if tag['Value'] != alt_env_name:
                        return False
            if tag['Key'] == 'Role':
                gotrole = True
                if self.role_name and tag['Value'] != self.role_name:
                    if not alt_env_name:
                        return False
        if not gotenv:
            return False
        if not gotrole and not alt_env_name:
            if self.role_name:
                return False
        elif force_role:
            if not self.role_name:
                return False
        return True

    def get_vm_args(self, args):
        """Check if args start with VM ID.

        returns: (vm-id, args)
        """
        if args and args[0][:2] == 'i-':
            return args[0], args[1:]
        main_vms = self.get_primary_vms()
        return main_vms[0], args

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

    def cmd_show_res(self, *cmdargs):
        """Show reserved instances.

        Group: info
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

    def load_prices(self):
        """Load pricing data from JS file.
        """
        price_fn = self.cf.getfile('price_data_file')
        if self._price_data is None:
            fn = os.path.join(self.git_dir, 'extra/cost/linux.js')
            data = open(fn, 'r').read()
            p1 = data.find('({')
            p2 = data.rfind('})')
            data = re.sub(r'([a-zA-Z0-9_]+):', r'"\1":', data[p1 + 1 : p2 + 1])
            data = data.replace(': .', ': 0.')
            self._price_data = json.loads(data)
        return self._price_data

    def find_price(self, region, vmtype, term='yrTerm1Standard', opt='noUpfront'):
        """Find price for specific offering
        """

        def findCol(lst, col, val):
            for obj in lst:
                if obj[col] == val:
                    return obj
            raise KeyError("findCol failed: " + col + " value not found: " + val)

        if vmtype == 'm3.large':
            return {'onDemandHourly': 0.146, 'reservedHourly': 0.146}
        if vmtype == 't3.large':
            return {'onDemandHourly': 0.0912, 'reservedHourly': 0.065}

        pdata = self.load_prices()
        rdata = findCol(pdata['config']['regions'], 'region', region)
        vmdata = findCol(rdata['instanceTypes'], 'type', vmtype)
        tdata = findCol(vmdata['terms'], 'term', term)
        optdata = findCol(tdata['purchaseOptions'], 'purchaseOption', opt)
        optprice = findCol(optdata['valueColumns'], 'name', 'effectiveHourly')
        stdprice = findCol(tdata['onDemandHourly'], 'purchaseOption', 'ODHourly')

        return {
            'onDemandHourly': float(stdprice['prices']['USD']),
            'reservedHourly': float(optprice['prices']['USD']),
        }

    def cmd_pricing_info(self):
        region = 'eu-west-1'
        client = self.get_boto3_client('pricing', region)
        pager = self.pager(client, 'describe_services', 'Services')
        for svc in pager(ServiceCode='AmazonEC2', FormatVersion='aws_v1'):
            print_json(svc)

    def cmd_products_info(self):
        print(boto3.__version__)
        region = 'eu-west-1'
        region = 'eu-central-1'
        client = self.get_boto3_client('pricing', region)
        pager = self.pager(client, 'get_products', 'PriceList')
        for svc in pager(ServiceCode='AmazonEC2', FormatVersion='aws_v1'):
            print_json(svc)

    def show_vmtype(self, region, vmtype, nActive, nReserved, names):
        """Shoe one vmtype stats with pricing.
        """
        nstep = 4
        odCount = 0
        if nActive > nReserved:
            odCount = nActive - nReserved
        price = self.find_price(region, vmtype)
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

    def cmd_show_vmtypes(self):
        """Show VM types.

        Group: info
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
            pager = self.pager(client, 'describe_instances', 'Reservations')
            for rv in pager(Filters=flist):
                for vm in rv['Instances']:
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

            printf('region: %s' % region)
            for vm_type in sorted(tmap):
                names = list(sorted(envmap[vm_type]))
                rawSum, curSum = self.show_vmtype(region, vm_type, tmap[vm_type], rmap.get(vm_type, 0), names)
                rawTotal += rawSum
                total += curSum
            for vm_type in rmap:
                if vm_type not in tmap:
                    rawSum, curSum = self.show_vmtype(region, vm_type, 0, rmap[vm_type], [])
                    rawTotal += rawSum
                    total += curSum
        printf('total: $%d/m  savings: $%d/m', total, rawTotal - total)

    def cmd_show_disktypes(self):
        """Show disk types.

        Group: info
        """

        def addVol(info, vol):
            vtype = vol['VolumeType']
            if vtype not in info:
                info[vtype] = 0
            info[vtype] += vol['Size']

        def show(name, info):
            parts = ['%s=%d' % (t, info[t]) for t in sorted(info)]
            if not parts:
                parts = ['-']
            printf('%s: %s', name, ', '.join(parts))

        all_regions = self.cf.getlist('all_regions')
        for region in all_regions:
            printf('-- %s --', region)

            envmap = {}
            vol_map = {}
            totals = {}
            gotVol = set()

            client = self.get_ec2_client(region)

            vol_pager = self.pager(client, 'describe_volumes', 'Volumes')
            for vol in vol_pager():
                vol_map[vol['VolumeId']] = vol

            vm_pager = self.pager(client, 'describe_instances', 'Reservations')
            for rv in vm_pager(Filters=[]):
                for vm in rv['Instances']:
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
                    show(rname, info)
                show('* total', totals)

                for vol_id in vol_map:
                    if vol_id not in gotVol:
                        printf("! Lost volume: %s", vol_id)

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
            slot = '/'.join(parts[1:-1])
            if slot_filter and not slot.startswith(slot_filter):
                continue

            head = self.s3_get_obj_head(bucket_name, kx['Key'])
            size = head['ContentLength']
            if slot not in slots:
                slots[slot] = 0
            slots[slot] += size
            if not summary_output:
                self.s3_show_obj_head(bucket_name, kx['Key'], head)

        if summary_output:
            for slot in sorted(slots):
                print("%s: %d" % (slot, slots[slot]))

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
        rnd = as_unicode(encode_base64(os.urandom(30)))
        mimedata = USERDATA.replace('RND', rnd)
        return mimedata

    def cmd_create(self, xtype):
        """Create instance.

        Group: vm
        """
        ids = self.vm_create_start(xtype)
        self.vm_create_finish(ids)
        return ids

    def vm_create_start(self, xtype):
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
        xname = 'vm.' + self.env_name
        if self.role_name:
            xname += '.' + self.role_name
        if not zone:
            zone = None
        ebs_optimized = self.cf.getboolean('ebs_optimized', False)
        disk_type = self.cf.get('disk_type', 'standard')

        disk_map = self.cf.getdict('disk_map', {})
        if not disk_map:
            disk_map = {'xvda': 'size=12'}

        # device name may be different for different AMIs
        root_device_name = 'xvda'
        res = client.describe_images(ImageIds=[image_id])
        if not res.get('Images'):
            eprintf("ERROR: no image: %r" % image_id)
            sys.exit(1)
        for img in res['Images']:
            root_device_name = img['RootDeviceName']

        devlog = []
        bdm = []
        klist = sorted(disk_map.keys())
        for dev in klist:
            val = disk_map[dev]
            ebs = {}
            bdev = {'DeviceName': dev}

            # seems something (ubuntu image?) overrides it otherwise
            if dev == 'xvda' and root_device_name != dev:
                bdev['DeviceName'] = root_device_name

            for opt in val.split(':'):
                k, v = opt.split('=')
                k = k.strip()
                v = v.strip()
                if k == 'size':
                    ebs['DeleteOnTermination'] = True
                    ebs['VolumeSize'] = int(v)
                    if 'VolumeType' not in ebs:
                        ebs['VolumeType'] = disk_type
                elif k == 'type':
                    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
                    # Values: standard, gp2, io1, st1, sc1
                    ebs['VolumeType'] = v
                elif k == 'local':
                    bdev['VirtualName'] = v
                elif k == 'encrypted':
                    ebs['Encrypted'] = bool(int(v))
            if ebs:
                bdev['Ebs'] = ebs
            bdm.append(bdev)

            devlog.append(dev)

        time_printf("AWS=%s Env=%s Role=%s Key=%s Image=%s(%s)",
                    self.cf.get('aws_main_account'),
                    self.env_name, self.role_name or '-', key_name,
                    image_name, image_id)

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

        self.cmd_classiclink(*ids)

        return ids

    def cmd_classiclink(self, *ids):
        """Set up classiclink.

        Group: vm
        """
        if not ids:
            ids = self.get_primary_vms()
        vpc_name = self.cf.get('classic_link_vpc', '')
        if not vpc_name:
            return

        time_printf("Setting up ClassicLink")
        vpc_id = self.vpc_lookup(vpc_name)

        sg_names = self.cf.getlist('classic_link_groups', '')
        sg_ids = self.sgroups_lookup(sg_names)

        client = self.get_ec2_client()
        for vm_id in ids:
            client.attach_classic_link_vpc(InstanceId=vm_id, VpcId=vpc_id, Groups=sg_ids)

    def vm_create_finish(self, ids):
        for vm_id in ids:
            self.new_ssh_key(vm_id)
        time_printf("Instances are ready")
        time.sleep(10)
        self._vm_map = {}
        return ids

    def cmd_create_root(self):
        """Create new root VM.

        Group: vm
        """
        if self.get_running_vms():
            raise UsageError('Env has running vms.  Please stop them before create-root.')

        self.modcmd_init('prep')

        start = time.time()
        ids = self.cmd_create('root')
        first = None
        for vm_id in ids:
            if not first:
                first = vm_id
            self.do_prep(vm_id, 'root')

        self.assign_vm(first, True)

        end = time.time()
        printf("VM ID: %s", ", ".join(ids))
        printf("Total time: %s", fmt_dur(end - start))

        return first

    def cmd_create_branch(self, *provider_ids):
        """Create non-root VM attached to existing root.

        Group: vm
        """
        start = time.time()

        self.modcmd_init('prep')

        ids = self.cmd_create('branch')
        first = None
        for vm_id in ids:
            if not first:
                first = vm_id
            self.do_prep(vm_id, 'branch', *provider_ids)

        end = time.time()
        printf("VM ID: %s", ", ".join(ids))
        printf("Total time: %d", int(end - start))
        return first

    def cmd_add_key(self, vm_id):
        """Extract SSH key from VM add EC2 tag.

        Group: vm
        """
        self.new_ssh_key(vm_id)

    def cmd_tag(self, res_id, name):
        """Set 'Name' tag.

        Group: vm
        """
        client = self.get_ec2_client()
        client.create_tags(Resources=[res_id], Tags=[{'Key': 'Name', 'Value': name}])

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
        vm_id, args = self.get_vm_args(args)
        if len(args) == 1:
            self.vm_exec(vm_id, args[0])
        else:
            self.vm_exec(vm_id, args or [])

    def cmd_ssh_admin(self, *args):
        """SSH to VM and run command (optional).

        Group: admin
        """
        vm_id, args = self.get_vm_args(args)
        if len(args) == 1:
            self.vm_exec(vm_id, args[0], use_admin=True)
        else:
            self.vm_exec(vm_id, args or [], use_admin=True)

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
            auth_groups = self.cf.getlist('authorized_user_groups', [])
            auth_users = self.cf.getlist('ssh_authorized_users', [])
            pat = self.cf.get('ssh_pubkey_pattern')
            script = []
            for user in sorted(set(auth_users)):
                fn = os.path.join(self.keys_dir, pat.replace('USER', user))
                pubkey = open(fn).read().strip()
                script.append(mk_sshuser_script(user, auth_groups, pubkey))
            return '\n'.join(script)

        try:
            return self.cf.get(key)
        except NoOptionError:
            raise UsageError("%s: key not found: %s" % (fname, key))

    def make_filter(self, vm_id, vmtype, extra_defs=None):
        # env description
        defs = {
            'INSTANCE_NAME': vm_id,
            'ENV_NAME': self.env_name,
            'VMTYPE': vmtype,
        }
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
            return self.load_gpg_file(fn)
        return open(fn, 'r').read()

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
        state_file = self.cf.get('tf_state_file')
        if self.options.verbose:
            printf("TF: %s", arg)
        val = tf_load_output_var(state_file, arg)
        if isinstance(val, list):
            raise UsageError("TF function got list param: %s" % kname)
        # work around tf dots in route53 data
        val = val.strip().rstrip('.')
        return val

    def conf_func_tfaz(self, arg, sect, kname):
        """Returns key from Terraform state file.

        Usage: ${TFAZ ! tfvar}
        """
        state_file = self.cf.get('tf_state_file')
        if self.options.verbose:
            printf("TFAZ: %s", arg)
        val = tf_load_output_var(state_file, arg)
        if not isinstance(val, list):
            raise UsageError("TFAZ function expects list param: %s" % kname)
        # FIXME: proper multi-AZ support
        return val[0]

    def cmd_prep(self, vm_id, xtype, *provider_ids):
        """Run prep.sh on vm.

        Group: admin
        """
        self.modcmd_init('prep')
        self.do_prep(vm_id, xtype, *provider_ids)

    def do_prep(self, vm_id, xtype, *provider_ids):
        """Do 'prep' command without init.
        """

        # small pause
        time.sleep(15)

        if xtype == 'branch':
            if provider_ids:
                root_id = provider_ids[0]
            else:
                root_id = self.get_primary_vms()[0]
            self.load_branch_vars(root_id)
        else:
            root_id = 'node_irrelevant'

        cmd = 'prep'
        #self.modcmd_init(cmd)
        self.modcmd_prepare([vm_id], cmd, vmtype=xtype, root_id=root_id)
        self.modcmd_run(cmd)

    def load_vm_file(self, vm_id, fn):
        load_cmd = ["sudo", "-nH", "cat", fn]
        return self.vm_exec(vm_id, load_cmd, get_output=True)

    def load_branch_vars(self, root_id):
        vmap = self.cf.getdict('load_branch_files', {})
        for vname, root_file in vmap.items():
            eprintf("Loading %s:%s", root_id, root_file)
            data = self.load_vm_file(root_id, root_file)
            self.cf.set(vname, as_unicode(data))

    _PREP_TGZ_CACHE = {}    # cmd->vmid->tgz
    _PREP_STAMP_CACHE = {}  # cmd->stamp

    def cmd_mod_test(self, cmd_name):
        """Test if payload can be created for command.

        Group: internal
        """
        fake_vm = 'i-XXXXXXXX'
        self.modcmd_init(cmd_name)
        self.modcmd_prepare([fake_vm], cmd_name)
        data = self._PREP_TGZ_CACHE[cmd_name][fake_vm]
        print("Data size: %d bytes" % len(data))
        return data

    def cmd_mod_dump(self, cmd_name):
        """Write tarball of command payload.

        Group: internal
        """
        fake_vm = 'i-XXXXXXXX'
        self.modcmd_init(cmd_name)
        self.modcmd_prepare([fake_vm], cmd_name)
        data = self._PREP_TGZ_CACHE[cmd_name][fake_vm]
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

    def has_modcmd(self, cmd_name):
        """Return true if command is configured from config.
        """
        return self.cf.has_section('cmd.%s' % cmd_name)

    def modcmd_init(self, cmd_name):
        """Run init script for command.
        """
        cmd_cf = self.cf.view_section('cmd.%s' % cmd_name)
        init_script = cmd_cf.get('init', '')
        if init_script:
            # let subprocess see current env
            subenv = os.environ.copy()
            subenv['VMTOOL_ENV_NAME'] = self.full_role
            run_successfully([init_script], cwd=self.git_dir, shell=True, env=subenv)

    def modcmd_prepare(self, args, cmd_name,
                       vmtype="unknown_type",
                       root_id='unknown_node',
                       root_private_ip='unknown_ip'):
        """Prepare data package for command.
        """
        cmd_cf = self.cf.view_section('cmd.%s' % cmd_name)
        stamp_dirs = cmd_cf.getlist('stamp_dirs', [])
        cmd_abbr = cmd_cf.get('command_tag', '')
        globs = cmd_cf.getlist('files', [])
        use_admin = cmd_cf.getboolean('use_admin', False)

        ids = []
        xargs = []

        for a in args:
            if a.startswith('i-') and not xargs:
                ids.append(a)
            else:
                xargs.append(a)

        if not ids:
            ids = self.get_primary_vms()

        self._PREP_TGZ_CACHE[cmd_name] = {}
        for vm_id in ids:
            self.newcmd_prepare_vm(cmd_name, vm_id, vmtype, globs, cmd_cf)

        self._PREP_STAMP_CACHE[cmd_name] = {
            'vmtype': vmtype,
            'root_id': root_id,
            'root_private_ip': root_private_ip,
            'ids': ids,
            'cmd_abbr': cmd_abbr,
            'stamp_dirs': stamp_dirs,
            'stamp': self.get_stamp(),
            'use_admin': use_admin,
            'args': xargs
        }

    def modcmd_run(self, cmd_name):
        """Send mod data to server and run it.
        """
        info = self._PREP_STAMP_CACHE[cmd_name]

        data_info = 0
        for vm_id in info['ids']:
            data = self._PREP_TGZ_CACHE[cmd_name][vm_id]
            if not data_info:
                data_info = 1
            self.run_mod_data(data, vm_id, info['vmtype'], info['root_id'], info['root_private_ip'],
                              use_admin=info['use_admin'])
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
    def newcmd_prepare_vm(self, cmd_name, vm_id, vmtype, globs, cmd_cf=None):
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

        dst = self.make_filter(vm_id, vmtype, defs)

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

        # create keys & certs
        for cert_ini in cert_fns:
            printf("Processing certs: %s", cert_ini)
            mdir = os.path.dirname(cert_ini)
            defs = {'env_name': self.env_name}
            if self.role_name:
                defs['role_name'] = self.role_name

            internal_dns_vm_name = self.cf.get('internal_dns_vm_name', '')
            if internal_dns_vm_name:
                zone_name = self.cf.get('internal_dns_zone_name')
                full_name = '%s.%s' % (internal_dns_vm_name, zone_name)
                defs['internal_dns_name'] = full_name

            keys = load_cert_config(cert_ini, self.load_ca_keypair, defs)
            for kname in keys:
                key, cert = keys[kname]
                key_fn = '%s/%s.key' % (mdir, kname)
                cert_fn = '%s/%s.crt' % (mdir, kname)
                dst.add_file_data(key_fn, key, 0o600)
                dst.add_file_data(cert_fn, cert, 0o600)

        # finish
        dst.close()
        tgz = dst.getvalue()
        self._PREP_TGZ_CACHE[cmd_name][vm_id] = tgz

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

    def run_mod_data(self, data, vm_id, vmtype, root_id, root_private_ip='some_ip', xargs=(), use_admin=False):

        run_user = 'root'

        launcher = './runner.sh "$@"'
        rm_cmd = 'rm -rf'
        if run_user:
            launcher = 'sudo -nH -u %s %s' % (run_user, launcher)
            rm_cmd = 'sudo -nH ' + rm_cmd

        args = [vm_id, root_id, vmtype, root_private_ip]
        args.extend(xargs)
        tmp_uuid = str(uuid.uuid4())

        time_printf("%s: Sending data - %d bytes", vm_id, len(data))
        decomp_script = 'mkdir -p "tmp/%s" && tar xzf - --warning=no-timestamp -C "tmp/%s"' % (tmp_uuid, tmp_uuid)
        self.vm_exec(vm_id, ["/bin/sh", "-c", decomp_script, 'decomp'], data, use_admin=use_admin)

        time_printf("%s: Running", vm_id)
        runit_script = 'cd "tmp/%s/vmlib" && %s && cd ../../.. && %s "tmp/%s"' % (tmp_uuid, launcher, rm_cmd, tmp_uuid)
        cmdline = ["/bin/sh", "-c", runit_script, 'runit'] + args
        self.vm_exec(vm_id, cmdline, None, use_admin=use_admin)

    def cmd_get_output(self, vm_id):
        """Print console output.

        Group: vm
        """
        client = self.get_ec2_client()
        res = client.get_console_output(InstanceId=vm_id)
        if res.get('Output'):
            print(res['Output'])

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

    def cmd_failover(self, branch_id, *old_root_ids):
        """Takeover for dead root.

        Group: vm
        """
        self.change_cwd_adv()

        if old_root_ids:
            # allow manual override
            root_ids = old_root_ids
        else:
            root_ids = self.get_dead_primary()
            if len(root_ids) > 1:
                raise UsageError('Dont know how to handle several roots')
        root_id = root_ids[0]

        # make sure it exists
        self.vm_lookup(branch_id)

        cmd = 'failover_promote_branch'
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_prepare([branch_id], cmd, vmtype='root', root_id=root_id,
                                root_private_ip='<dead-ip>')
            self.modcmd_run(cmd)

        self.raw_assign_vm(branch_id)

        return branch_id

    def cmd_takeover(self, branch_id, *root_ids):
        """Switch root to another node.

        Group: vm
        """
        self.change_cwd_adv()

        if root_ids:
            root_id = root_ids[0]
        else:
            root_id = self.get_primary_vms()[0]

        if root_id == branch_id:
            raise UsageError("%s is already primary" % branch_id)

        root_vm = self.vm_lookup(root_id)
        root_tags = self.load_tags(root_vm)
        root_private_ip = root_vm['PrivateIpAddress']

        self.old_commit = root_tags.get('Commit', '')
        if self.old_commit.find(':') > 0:
            self.old_commit = self.old_commit.split(':')[1]

        # make sure it exists
        self.vm_lookup(branch_id)

        cmd = 'takeover1_prepare_root'
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_prepare([root_id], cmd, vmtype='branch', root_id=root_id,
                                root_private_ip=root_private_ip)
            self.modcmd_run(cmd)

        cmd = 'takeover1_prepare_branch'
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_prepare([branch_id], cmd, vmtype='root', root_id=root_id,
                                root_private_ip=root_private_ip)
            self.modcmd_run(cmd)

        cmd = 'takeover2_finish_root'
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_prepare([root_id], cmd, vmtype='branch', root_id=root_id,
                                root_private_ip=root_private_ip)
            self.modcmd_run(cmd)

        cmd = 'takeover2_finish_branch'
        if self.has_modcmd(cmd):
            self.modcmd_init(cmd)
            self.modcmd_prepare([branch_id], cmd, vmtype='root', root_id=root_id,
                                root_private_ip=root_private_ip)
            self.modcmd_run(cmd)

        self.raw_assign_vm(branch_id)

        return root_id

    def cmd_full_upgrade(self):
        """Replace node, stop old one

        Group: vm
        """
        old_root = self.cmd_safe_upgrade()
        time.sleep(15)
        self.cmd_drop_node(old_root)

    def cmd_safe_upgrade(self):
        """Keep node running and in cascade

        Group: vm
        """
        vm_id = self.cmd_create_branch()
        old_root = self.cmd_takeover(vm_id)
        #self.vm_exec(vm_id, ["sudo", "-nH", "/etc/init.d/skytools3", "restart"])

        if self.new_commit and self.old_commit:
            show_commits(self.old_commit, self.new_commit, [], self.git_dir)

        return old_root

    def cmd_drop_node(self, vm_id):
        """Drop database node from cascade.

        Group: vm
        """
        printf("Drop simple node: %s", vm_id)
        #self.run_console_cmd('londiste', [vm_id, 'drop-node', vm_id])
        self.cmd_stop(vm_id)

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
                self.change_cwd_adv()
                self.modcmd_init(cmd)
                self.modcmd_prepare(cmdargs, cmd)
                self.modcmd_run(cmd)
            else:
                self.run_console_cmd(cmd, cmdargs)
        else:
            super(VmTool, self).work()

    def run_console_cmd(self, cmd, cmdargs):
        cmd_cf = self.cf.view_section('cmd.%s' % cmd)
        cmdline = cmd_cf.get('vmrun')
        argparam = cmd_cf.get('vmrun_arg_param', '')

        fullcmd = shlex.split(cmdline)
        vm_id, args = self.get_vm_args(cmdargs)
        if args:
            if argparam:
                fullcmd = fullcmd + [argparam, ' '.join(args)]
            else:
                fullcmd = fullcmd + args
        self.vm_exec(vm_id, fullcmd)

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
        client = self.get_ec2_client()

        name = self.cf.get('image_name')
        desc = self.cf.get('image_desc')
        copy_regions = self.cf.getlist('image_copy_regions', [])
        time_printf("BuildImage: name=%s", name)

        image_id = self.get_image_id(name)
        if image_id:
            raise UsageError("Image with this name already exists")

        vm_id = self.cmd_create_root()
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
        for img in sorted(res['Images'], key=lambda img: img['CreationDate']):
            self.show_image(img)

    def show_image(self, img):
        printf("%s state=%s region=%s name=%s desc=%s",
               img['ImageId'], img['State'], '?', img['Name'], img.get('Description') or '-')
        printf("  type=%s/%s/%s/%s/%s location=%s",
               img['VirtualizationType'], img['RootDeviceType'],
               img['Architecture'], img['Hypervisor'],
               img['Public'] and 'public' or 'private',
               img['ImageLocation'])
        printf("  ctime=%s", img['CreationDate'])
        printf("  tags=%s", self.load_tags(img))
        printf("  disk_mapping:")
        for bdt in img['BlockDeviceMappings']:
            ebs = bdt.get('Ebs') or {}
            if ebs.get('SnapshotId'):
                printf("    %s: snapshot=%s size=%s",
                       bdt.get('DeviceName'), ebs.get('SnapshotId'), ebs.get('VolumeSize'))
            else:
                printf("    %s: ephemeral=%s",
                       bdt.get('DeviceName'), bdt.get('VirtualName'))

    def cmd_show_images_debian(self):
        """Show images

        Group: image
        """
        # https://wiki.debian.org/Cloud/AmazonEC2Image
        client = self.get_ec2_client()
        res = client.describe_images(Owners=['379101102735'], Filters=[
            {'Name': 'architecture', 'Values': ['x86_64']},
            {'Name': 'virtualization-type', 'Values': ['hvm']},  # paravirtual / hvm
        ])
        for img in sorted(res['Images'], key=lambda img: img['CreationDate']):
            self.show_image(img)

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

