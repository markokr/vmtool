"""Utility functions for vmtool.
"""

import sys
import errno
import gzip
import hashlib
import hmac
import io
import json
import logging
import os
import re
import subprocess
import time
import binascii
import datetime


__all__ = ['hash_known_host', 'ssh_add_known_host', 'parse_console', 'fmt_dur',
           'gz_compress', 'rsh_quote', 'printf', 'eprintf']


def as_unicode(s):
    if not isinstance(s, bytes):
        return s
    return s.decode('utf8')


def as_bytes(s):
    if not isinstance(s, bytes):
        return s.encode('utf8')
    return s


def encode_base64(data):
    return binascii.b2a_base64(data).strip()

#
# SSH known_hosts management
#


def hash_known_host(host, old_entry=None):
    """Hash hostname or ip for SSH known_hosts file.
    """
    if old_entry:
        salt = binascii.a2b_base64(old_entry[3:].split('|', 1)[0])
    else:
        salt = os.urandom(20)
    h = hmac.new(salt, as_bytes(host), hashlib.sha1).digest()
    s64 = as_unicode(encode_base64(salt))
    h64 = as_unicode(encode_base64(h))
    return '|1|%s|%s' % (s64, h64)


def ssh_add_known_host(kh_file, dns, ip, ktype, kval, vm_id, hash_hosts=True):
    fdir = os.path.dirname(kh_file)
    if not os.path.isdir(fdir):
        os.makedirs(fdir, 0o700, exist_ok=True)

    space_rc = re.compile('[ \t]+')
    new_file = []
    if os.path.isfile(kh_file):
        found_ip = False
        found_dns = False
        drops = False
        cur_key = (ktype, kval)
        lines = 0
        for ln in open(kh_file).readlines():
            lines += 1
            xln = ln.strip()
            if not xln or xln[0] == '#':
                new_file.append(ln)
                continue
            t = space_rc.split(xln)
            adr = t[0].strip()
            kt = t[1].strip()
            kv = t[2].strip()
            old_key = (kt, kv)
            if kt != ktype and ktype != 'ecdsa-sha2-nistp256':
                pass
            elif adr.startswith('|1|'):
                if ip and adr == hash_known_host(ip, adr):
                    if old_key == cur_key:
                        found_ip = True
                    else:
                        drops = True
                        continue  # drop
                elif dns and adr == hash_known_host(dns, adr):
                    if old_key == cur_key:
                        found_dns = True
                    else:
                        drops = True
                        continue  # drop
            else:
                if ip and adr == ip:
                    if old_key == cur_key:
                        found_ip = True
                    else:
                        drops = True
                        continue  # drop
                elif dns and adr == dns:
                    if old_key == cur_key:
                        found_dns = True
                    else:
                        drops = True
                        continue  # drop
            new_file.append(ln)

        if found_dns and found_ip and not drops:
            # keys already exist
            return

        # clean too big file
        if lines > 100:
            new_file = new_file[-20:]

    # keys dont exist
    if hash_hosts:
        ipln = "%s %s %s %s\n" % (hash_known_host(dns), ktype, kval, vm_id)
        dnsln = "%s %s %s %s\n" % (hash_known_host(ip), ktype, kval, vm_id)
    else:
        ipln = "%s %s %s %s\n" % (dns, ktype, kval, vm_id)
        dnsln = "%s %s %s %s\n" % (ip, ktype, kval, vm_id)
    new_file.append(ipln)
    new_file.append(dnsln)

    write_atomic(kh_file, ''.join(new_file))


#
# Parse SSH keys from EC2 console.
#


def parse_console(vm_console, key_types=('ssh-ed25519', 'ecdsa-sha2-nistp256')):
    """Parse SSH keys from AWS vm console.
    """
    begin = "-----BEGIN SSH HOST KEY KEYS-----"
    end = "-----END SSH HOST KEY KEYS-----"
    keys = []

    if not vm_console:
        return None

    # find SSH signatures
    p1 = vm_console.find(begin)
    if p1 < 0:
        return None
    p2 = vm_console.find(end, p1)
    if p2 < 0:
        return None

    # parse lines
    klines = vm_console[p1 + len(begin):p2]
    for kln in klines.split('\n'):
        pos = kln.find('ecdsa-')
        if pos < 0:
            pos = kln.find('ssh-')
            if pos < 0:
                continue
        kln = kln[pos:].strip()
        ktype, kcert, kname = kln.split(' ')
        if ktype not in key_types:
            continue
        keys.append((ktype, kcert))

    if not keys:
        raise IOError("Failed to get SSH keys")

    return keys


#
# Random stuff
#


def gz_compress(filename, data):
    buf = io.BytesIO()
    g = gzip.GzipFile(filename, fileobj=buf, compresslevel=6, mode="w")
    g.write(data)
    g.close()
    return buf.getvalue()


def rsh_quote(args):
    if not isinstance(args, (tuple, list)):
        raise ValueError('rsh_quote needs list of args')
    res = []
    rc_bad = re.compile(r'[^\-\w.,:_=/]')
    for a in args:
        if rc_bad.search(a):
            a = "'%s'" % a.replace("'", "'\\''")
        elif not a:
            a = "''"
        res.append(a)
    return res


def hmac_sha256(key, data):
    h = hmac.HMAC(as_bytes(key), as_bytes(data), hashlib.sha256)
    return h.digest()


def printf(msg, *args):
    if args:
        msg = msg % args
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


def eprintf(msg, *args):
    if args:
        msg = msg % args
    sys.stderr.write(msg + '\n')
    sys.stderr.flush()


def time_printf(msg, *args):
    t = time.gmtime()
    tstr = "%02d:%02d:%02d *** " % (t.tm_hour, t.tm_min, t.tm_sec)
    if args:
        msg = msg % args
    sys.stdout.write(tstr + msg + '\n')
    sys.stdout.flush()


def run_successfully(cmd, **kwargs):
    try:
        subprocess.check_call(cmd, **kwargs)
    except subprocess.CalledProcessError:
        logging.error("Command failed: %r", cmd)
        sys.exit(1)


def local_cmd(cmd):
    return subprocess.check_output(cmd).decode('utf8')


def _json_default(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError("unserializable object: " + repr(obj))


def print_json(obj):
    print(json.dumps(obj, indent=4, default=_json_default, sort_keys=True))


# non-win32
def write_atomic(fn, data, bakext=None, mode='b'):
    """Write file with rename."""

    if mode not in ['', 'b', 't']:
        raise ValueError("unsupported fopen mode")

    # write new data to tmp file
    fn2 = fn + '.new'
    f = open(fn2, 'w' + mode)
    f.write(as_bytes(data))
    f.close()

    # link old data to bak file
    if bakext:
        if bakext.find('/') >= 0:
            raise ValueError("invalid bakext")
        fnb = fn + bakext
        try:
            os.unlink(fnb)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
        try:
            os.link(fn, fnb)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise

    # win32 does not like replace
    if sys.platform == 'win32':
        try:
            os.remove(fn)
        except:
            pass

    # atomically replace file
    os.rename(fn2, fn)


def fmt_dur(dur):
    """Format time duration.

    >>> dlong = ((27 * 24 + 2) * 60 + 38) * 60 + 43
    >>> [fmt_dur(v) for v in (0.001, 1.1, dlong, -5)] == ['0s', '1s', '27d2h38m43s', '-5s']
    True
    """
    res = []
    if dur < 0:
        res.append('-')
        dur = -dur
    tmp, secs = divmod(int(dur), 60)
    tmp, mins = divmod(tmp, 60)
    days, hours = divmod(tmp, 24)
    for (val, unit) in ((days, 'd'), (hours, 'h'), (mins, 'm'), (secs, 's')):
        if val:
            res.append('%d%s' % (val, unit))
    if not res:
        return '0s'
    return ''.join(res)


