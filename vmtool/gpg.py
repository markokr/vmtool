
import os
import subprocess

from vmtool.scripting import UsageError
from vmtool.util import printf, as_unicode

__all__ = ['load_gpg_file']

_gpg_cache = {}


def load_gpg_file(fn, verbose):
    if fn in _gpg_cache:
        return _gpg_cache[fn]
    if verbose:
        printf("GPG: %s", fn)
    # file data directly
    if not os.path.isfile(fn):
        raise UsageError("GPG file not found: %s" % fn)
    data = popen(['gpg', '-q', '-d', '--batch', fn])
    res = as_unicode(data)
    _gpg_cache[fn] = res
    return res


def popen(cmd, input_data=None, **kwargs):
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
