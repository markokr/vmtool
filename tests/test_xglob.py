
import os.path

def test_xfilter():
    from vmtool.xglob import xfilter

    assert xfilter('.foo*.txt?', ['.foo0_txt0', '.foo1.txt2']) == ['.foo1.txt2']
    assert xfilter('*foo*.txt?', ['qwe', '.foo1.txt2']) == []


def _xglob(pat):
    from vmtool.xglob import xglob

    return [os.path.basename(f) for f in xglob(pat)]


def test_xglob():
    dn = os.path.dirname(__file__)
    assert _xglob(dn + '/*glob*.py') == ['test_xglob.py']
    assert _xglob(dn + '/**/*glob*.py') == ['test_xglob.py']

