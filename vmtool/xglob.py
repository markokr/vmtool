"""Extended glob.

Basic syntax:

*       - anything, except /
?       - any char, except /
[]      - char in set
[!]     - char not in set

Extended syntax:

**      - any subdir
()      - grouping
|       - or

"""

import sys
import os
import os.path
import re

__all__ = ['xglob']


def re_escape(s):
    """Escape regex meta-characters"""
    return re.sub(r'[][(){}\\.?*+|^$]', lambda m: '\\' + m.group(0), s)


def has_magic(pat):
    """Contains glob magic chars."""
    return re.search(r'[*?[()|]', pat) is not None


def xcompile(pat):
    """Convert glob/fnmatch pattern to compiled regex."""
    plen = len(pat)
    pos = 0
    res = []
    while pos < plen:
        c = pat[pos]
        pos += 1
        if c == '?':
            x = '.'
        elif c == '*':
            x = '.*'
            if res and res[-1] == x:
                continue
        elif c in '()|':
            x = c
        elif c == '[':
            x = c

            # first char is ! or ^
            if pos < plen and (pat[pos] == '!' or pat[pos] == '^'):
                x += '^'
                pos += 1

            # first char is ]
            if pos < plen and pat[pos] == ']':
                x += r'\]'
                pos += 1

            # loop until ]
            while pos < plen:
                c = pat[pos]
                pos += 1
                if c == ']':
                    x += ']'
                    break
                x += re_escape(c)
        else:
            # not ?*(|)[
            x = re_escape(c)
        res.append(x)
    xre = r'\A' + ''.join(res) + r'\Z'
    return re.compile(xre, re.S)


def xfilter(pattern, names):
    """Filter name list based on glob pattern.
    """
    rc = xcompile(pattern)
    if pattern[0] != '.':
        names = [n for n in names if n[0] != '.' and rc.match(n)]
    else:
        names = [n for n in names if rc.match(n)]
    return names


def dirglob_nopat(dirname, basename, need_dirs):
    """File name without pattern."""
    res = []
    if basename == '':
        if os.path.isdir(dirname):
            res.append(basename)
    elif os.path.lexists(os.path.join(dirname, basename)):
        res.append(basename)
    return res


def dirglob_pat(dirname, pattern, need_dirs):
    """File name with pattern."""
    if not isinstance(pattern, bytes) and isinstance(dirname, bytes):
        dirname = dirname.decode(sys.getfilesystemencoding() or sys.getdefaultencoding())
    try:
        names = os.listdir(dirname)
    except os.error:
        return []
    return xfilter(pattern, names)


def dirglob_subtree(dirname, pattern, need_dirs):
    """File name is '**'."""
    res = []
    for dp, dnames, fnames in os.walk(dirname, topdown=True):
        if dp == dirname:
            res.append('')
            basedir = ''
        else:
            basedir = dp[len(dirname) + 1:] + os.path.sep
        if not need_dirs:
            for fn in fnames:
                if fn[0] != '.':
                    res.append(basedir + fn)

        skip_dirs = []
        for dn in dnames:
            if dn[0] != '.':
                res.append(basedir + dn)
            else:
                skip_dirs.append(dn)

        # don't recurse into dot-dirs
        for dn in skip_dirs:
            dnames.remove(dn)

    return res


def xglob(pat, _dirs_only=False):
    """Extended glob.

    Supports ** and (|) in pattern.

    Acts as iterator.
    """

    # plain path?
    if not has_magic(pat):
        if os.path.lexists(pat):
            yield pat
        return

    # split pattern
    dn, bn = os.path.split(pat)
    if not dn:
        # pattern without dir part
        for name in dirglob_pat(os.curdir, bn, _dirs_only):
            yield name
        return

    # expand dir part
    if has_magic(dn):
        dirs = xglob(dn, True)
    else:
        dirs = iter([dn])

    # decide how to expand file part
    if bn == '**':
        dirglob = dirglob_subtree
    elif has_magic(bn):
        dirglob = dirglob_pat
    else:
        dirglob = dirglob_nopat

    # loop over files
    for dn in dirs:
        for name in dirglob(dn, bn, _dirs_only):
            yield os.path.join(dn, name).replace(os.path.sep, '/')


def main():
    for pat in sys.argv[1:]:
        for fn in xglob(pat):
            print(fn)


if __name__ == '__main__':
    main()

