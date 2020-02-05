"""Extended glob.

Basic syntax:

*       - anything, except /
?       - any char, except /
[...]   - char in set
[!...]  - char not in set

Recursion syntax (globstar):

**      - recurse into subdirectories

Extended syntax (extglob):

?()     - zero or one of group
*()     - any number occurances of group
+()     - one or more occurances of group
@()     - one occurances of group
!()     - no occurance of group
|       - separate group elements

"""

import sys
import os
import os.path
import re
import functools

__all__ = ['xglob', 'xfilter']


# special regex symbols
_RXMAGIC = re.compile(r'[][(){}\\.?*+|^$]')

# glob magic
_GMAGIC = re.compile(r'[][()*?]')

# glob tokens
_GTOK = re.compile(r"""
 [*?+@!] \( |
 \[ [!\]]? . [^\]]* \] |
 [*?|)]
""", re.X | re.S)

# map glob syntax to regex syntax
_PARENS = {
    '?(': ['(?:', ')?'],
    '*(': ['(?:', ')*'],
    '+(': ['(?:', ')+'],
    '@(': ['(?:', ')'],
    '!(': ['(?!', ')'],
}


def escape(s):
    """Escape glob meta-characters.
    """
    return _GMAGIC.sub(r'[\g<0>]', s)


def re_escape(s):
    """Escape regex meta-characters.
    """
    return _RXMAGIC.sub(r'\\\g<0>', s)


def has_magic(pat):
    """Contains glob magic chars.
    """
    return _GMAGIC.search(pat) is not None


def _nomatch(name):
    """Invalid pattern does not match anything.
    """
    return None


@functools.lru_cache(maxsize=256, typed=True)
def _compile(pat):
    """Convert glob/fnmatch pattern to compiled regex.
    """
    plen = len(pat)
    pos = 0
    res = []
    parens = []
    while pos < plen:
        m = _GTOK.search(pat, pos)
        if not m:
            res.append(re_escape(pat[pos:]))
            break
        p1 = m.start()
        if p1 > pos:
            res.append(re_escape(pat[pos:p1]))
        pos = m.end()

        c = m.group(0)
        if len(c) > 1:
            if c[0] == '[':
                if c[1] == '!':
                    x = '[^' + re_escape(c[2:-1]) + ']'
                else:
                    x = '[' + re_escape(c[1:-1]) + ']'
            elif c in _PARENS:
                x = _PARENS[c][0]
                parens.append(_PARENS[c][1])
            else:
                x = re_escape(c)
        elif c == '?':
            x = '.'
        elif c == '*':
            x = '.*'
            if res and res[-1] == x:
                continue
        elif c == ')' and parens:
            x = parens.pop()
        elif c == '|' and parens:
            x = c
        else:
            x = re_escape(c)
        res.append(x)

    if parens:
        return _nomatch

    xre = r'\A' + ''.join(res) + r'\Z'
    return re.compile(xre, re.S).match


def xfilter(pat, names):
    """Filter name list based on glob pattern.
    """
    matcher = _compile(pat)
    if pat[0] != '.':
        for n in names:
            if n[0] != '.' and matcher(n):
                yield n
    else:
        for n in names:
            if matcher(n):
                yield n


def dirglob_nopat(dirname, basename, dirs_only):
    """File name without pattern.
    """
    if basename == '':
        if os.path.isdir(dirname):
            yield basename
    elif os.path.lexists(os.path.join(dirname, basename)):
        yield basename


def dirglob_pat(dirname, pattern, dirs_only):
    """File name with pattern.
    """
    if not isinstance(pattern, bytes) and isinstance(dirname, bytes):
        dirname = dirname.decode(sys.getfilesystemencoding() or sys.getdefaultencoding())
    try:
        names = os.listdir(dirname)
    except os.error:
        return iter([])
    return xfilter(pattern, names)


def dirglob_subtree(dirname, pattern, dirs_only):
    """File name is '**', recurse into subtrees.
    """
    for dp, dnames, fnames in os.walk(dirname, topdown=True):
        if dp == dirname:
            basedir = ''
            yield basedir
        else:
            basedir = dp[len(dirname) + 1:] + os.path.sep

        if not dirs_only:
            for fn in fnames:
                if fn[0] != '.':
                    yield basedir + fn

        filtered = []
        for dn in dnames:
            if dn[0] != '.':
                filtered.append(dn)
                yield basedir + dn
        dnames[:] = filtered


def _xglob(pat, dirs_only=False):
    """Internal implementation.
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
        for name in dirglob_pat(os.curdir, bn, dirs_only):
            yield name
        return

    # expand dir part
    if has_magic(dn):
        dirs = _xglob(dn, True)
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
        for name in dirglob(dn, bn, dirs_only):
            yield os.path.join(dn, name).replace(os.path.sep, '/')


def xglob(pat):
    """Extended glob.

    Supports ** and extended glob syntax in pattern.

    Acts as iterator.
    """
    return _xglob(pat)


def main():
    for pat in sys.argv[1:]:
        for fn in xglob(pat):
            print(fn)


if __name__ == '__main__':
    main()

