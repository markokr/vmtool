
import os.path
import vmtool.xglob


def xfilter(pat, names):
    return list(vmtool.xglob.xfilter(pat, names))


def xglob(pat):
    return [os.path.basename(f) for f in vmtool.xglob.xglob(pat)]


def test_xfilter():
    assert xfilter('.foo*.txt?', ['.foo0_txt0', '.foo1.txt2']) == ['.foo1.txt2']
    assert xfilter('*foo*.txt?', ['qwe', '.foo1.txt2']) == []

    assert xfilter('foo@(a|b).', ['fooa.', 'foob.', 'fooc.', 'foo.', 'fooaa']) == ['fooa.', 'foob.']
    assert xfilter('x+(a|b)', ['x', 'xa', 'xb', 'xc', 'xaab', 'xabaz']) == ['xa', 'xb', 'xaab']
    assert xfilter('x!(a|b)*', ['x', 'xa', 'xb', 'xc', 'xaab']) == ['x', 'xc']
    assert xfilter('x?(a|b)z', ['xz', 'xaz', 'xbz', 'xcz']) == ['xz', 'xaz', 'xbz']
    assert xfilter('x*(a|b)z', ['xz', 'xaz', 'xbaz', 'xcz']) == ['xz', 'xaz', 'xbaz']


def test_xglob():
    dn = os.path.dirname(__file__)
    assert xglob(dn + '/*glob*.py') == ['test_xglob.py']
    assert xglob(dn + '/**/*glob*.py') == ['test_xglob.py']

