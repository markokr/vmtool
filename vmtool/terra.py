"""Access terraform state.
"""

import json

__all__ = ['tf_load_output_var', 'tf_load_all_vars']


def tf_load_output_var(state_file, name):
    keys = tf_load_all_vars(state_file)
    if name not in keys:
        raise KeyError('%s: TF module does not have output: %s' % (state_file, name))
    return keys[name]


def tf_load_all_vars(state_file):
    res = {}
    state = json.load(open(state_file))
    for mod in state['modules']:
        path = mod['path']
        if path == ['root']:
            # top-level resource
            resmap = mod.get('resources', {})
            for resname in resmap:
                attmap = resmap[resname].get('primary', {}).get('attributes', {})
                for attname in attmap:
                    fqname = '%s.%s' % (resname, attname)
                    res[fqname] = attmap[attname]
        elif path[0] == 'root':
            # module
            mpath = '.'.join(path[1:])
            modvars = mod.get('outputs', {})
            for keyname in modvars:
                fqname = 'module.%s.%s' % (mpath, keyname)
                res[fqname] = modvars[keyname]['value']
    return res

