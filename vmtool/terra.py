"""Access terraform state.
"""

import json

__all__ = ['tf_load_output_var', 'tf_load_all_vars']


def _get_module(state, path):
    for mod in state['modules']:
        if mod['path'] == path:
            return mod
    raise ValueError('TF module not found: %r' % path)


def tf_load_output_var(state_file, name):
    state = json.load(open(state_file))

    path = ['root']

    parts = name.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid param format: %s' % name)
    attname = parts[2]

    if parts[0] == 'module':
        path.append(parts[1])
        mod = _get_module(state, path)
        modvars = mod['outputs']
        if attname in modvars:
            return modvars[attname]['value']
        raise ValueError('TF module does not have output: %s' % name)

    resname = parts[0] + '.' + parts[1]

    mod = _get_module(state, path)
    res = mod['resources'].get(resname)
    if not res:
        raise ValueError('TF resource not found: %s' % name)

    val = res['primary']['attributes'].get(attname)
    if val is None:
        raise ValueError('TF attribute not found: %s' % name)
    return val


def tf_load_all_vars(state_file):
    res = {}
    state = json.load(open(state_file))
    for mod in state['modules']:
        if len(mod['path']) < 2:
            resmap = mod.get('resources', {})
            for resname in resmap:
                attmap = resmap[resname].get('primary', {}).get('attributes', {})
                for attname in attmap:
                    fqname = '%s.%s' % (resname, attname)
                    res[fqname] = attmap[attname]
        else:
            modvars = mod.get('outputs', {})
            for keyname in modvars:
                fqname = 'module.%s.%s' % (mod['path'][1], keyname)
                res[fqname] = modvars[keyname]['value']
    return res

