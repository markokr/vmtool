# asd

from vmtool.config import Config

def _up(val, sect, opt):
    return val.upper()

_FUNCS = {
    'UP': _up,
}

def load(data, main_section='test', filename=None, user_defs=None, override=None, ignore_defs=False, func_map=None):
    cf = Config(main_section=main_section, filename=filename, user_defs=user_defs,
                override=override, ignore_defs=ignore_defs, func_map=func_map)
    cf.cf.read_string(data)
    return cf


_sample_cf = '''
[test]
foo = 1
foo0 = zero
foo1 = one
bar = 0
gaz = ${foo${bar}}
goz = ${foo${foo}}
xone = ${UP ! ${foo1}}

yfoo = ${other:foo}

[other]
foo = zab
'''

def test_config():
    cf = load(_sample_cf, func_map=_FUNCS)
    assert cf.get('foo') == '1'
    assert cf.getint('foo') == 1
    assert cf.get('gaz') == 'zero'
    assert cf.get('goz') == 'one'
    assert cf.get('xone') == 'ONE'
    assert cf.get('yfoo') == 'zab'

