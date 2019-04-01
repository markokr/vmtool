"""TarBall that filters input data.
"""

import re
import os
import subprocess
import binascii

from vmtool.util import hmac_sha256, as_bytes
from vmtool.tarball import TarBall


def gen_password(username, password_master):
    if not password_master:
        raise Exception("password_master not configured")
    src = b"\000%s\377" % username.encode('utf8')
    h = hmac_sha256(password_master, src)
    return binascii.b2a_base64(h).decode('ascii').rstrip().rstrip('=')


class TarFilter(TarBall):
    tag = re.compile(b'{{ ( [^{}]+ ) }}', re.X)

    _password_master = None

    def __init__(self, key_lookup_func, key_lookup_arg):
        super(TarFilter, self).__init__()
        self.live = 0
        self.key_lookup_func = key_lookup_func
        self.key_lookup_arg = key_lookup_arg

    def set_live(self, is_live):
        self.live = is_live

    def add_output(self, fpath, cmd):
        """Read command stdout, check for exit code.
        """
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        buf = p.communicate()[0]
        if p.returncode != 0:
            raise Exception("command failed: %r" % cmd)
        self.add_file_data(fpath, buf)

    def filter_data(self, fname, data):
        #pfx = 'setup-final'
        if fname[:2] == './':
            fname = fname[2:]
        if fname == '.':
            return fname, None
        #fname2 = 'setup-final/' + fname
        fname2 = fname
        p, ext = os.path.splitext(fname)
        if ext in ('.pyc', '.doctree', '.pickle', '.swp'):
            return None, None
        if fname.startswith('doc/html'):
            return None, None
        if fname.startswith('doc/tmp'):
            return None, None
        if ext in ('.png', '.jpg', '.gif'):
            if fname.startswith('doc/'):
                return None, None
            return fname2, data
        if not data:
            return fname2, data

        # seems text data, check if it uses templating
        if ext == '.tmpl':
            fname2 = p
        elif data.find(b"VMTMPL", 0, 100) < 0:
            return fname2, data

        # replace template values
        res = []
        pos = 0
        while pos < len(data):
            m = self.tag.search(data, pos)
            if not m:
                break
            p1 = m.start()
            res.append(data[pos:p1])
            pos = m.end()
            k = m.group(1).strip()
            v = self.key_lookup(k, fname)
            res.append(as_bytes(v))

        res.append(data[pos:])
        data = b''.join(res)
        return fname2, data

    def _lazy_lookup(self, key, fname):
        val = self.key_lookup_func(self.key_lookup_arg, key, fname)
        if val is not None:
            return val
        raise KeyError("Config key not found: %s / %s" % (fname, key))

    def _gen_password(self, username, fname):
        if self._password_master is None:
            self._password_master = self._lazy_lookup('password_master', fname)
        return gen_password(username, self._password_master)

    def key_lookup(self, key, fname):
        if isinstance(key, bytes):
            key = key.decode('utf8')
        t = key.split(':', 1)
        if len(t) == 1:
            return self._lazy_lookup(key, fname)
        kfunc = t[0].strip()
        arg = t[1].strip()
        if kfunc == 'PSW':
            psw = self._gen_password(arg, fname)
            return psw
        elif kfunc == 'LIVE':
            v1, v2 = arg.split('|', 1)
            if self.live:
                return v1.strip()
            else:
                return v2.strip()
        elif kfunc == 'ALT':
            v1, v2 = arg.split('|', 1)
            v1, v2 = v1.strip(), v2.strip()
            try:
                val = self.key_lookup(v1, fname).strip()
            except:
                val = None
            return val or v2
        elif kfunc == 'CLEAN':
            v = self.key_lookup(arg, fname)
            v = ' '.join(v.split())
            return v.strip()
        elif kfunc == 'CLEANWS':
            v = self.key_lookup(arg, fname)
            v = ''.join(v.split())
            return v.strip()
        elif kfunc == 'STRIP':
            v = self.key_lookup(arg, fname)
            return v.strip()
        elif kfunc == 'RXESC':
            v = self.key_lookup(arg, fname).strip()
            return v.replace('\\', '\\\\').replace('.', '\\.')
        elif kfunc == 'SPLIST':
            v = self.key_lookup(arg, fname).strip()
            vals = [e.strip() for e in v.split(',') if e.strip()]
            return ' '.join(vals)
        else:
            raise KeyError("%s: Unknown config op: %s" % (fname, kfunc))

