"""Access terraform state.
"""

import json

__all__ = ["tf_load_output_var", "tf_load_all_vars"]


def tf_load_output_var(state_file, name):
    keys = tf_load_all_vars(state_file)
    if name not in keys:
        raise KeyError("%s: TF module does not have output: %s" % (state_file, name))
    return keys[name]


def _load_state_v3(state):
    res = {}
    for mod in state["modules"]:
        path = mod["path"]
        if path == ["root"]:
            # top-level resource
            resmap = mod.get("resources", {})
            for resname in resmap:
                attmap = resmap[resname].get("primary", {}).get("attributes", {})
                for attname in attmap:
                    fqname = "%s.%s" % (resname, attname)
                    res[fqname] = attmap[attname]
        elif path[0] == "root":
            # module
            mpath = ".".join(path[1:])
            modvars = mod.get("outputs", {})
            for keyname in modvars:
                fqname = "module.%s.%s" % (mpath, keyname)
                res[fqname] = modvars[keyname]["value"]
    return res


def flatten(dst, k, v):
    if isinstance(v, dict):
        for kx, vx in v.items():
            flatten(dst, "%s.%s" % (k, kx), vx)
    else:
        dst[k] = v
    return dst


def _load_state_v4(state):
    res = {}
    for k, v in state["outputs"].items():
        flatten(res, k, v["value"])
    return res


_tf_cache = {}


def tf_load_all_vars(state_file):
    if state_file in _tf_cache:
        return _tf_cache[state_file]
    with open(state_file, encoding="utf8") as f:
        state = json.load(f)
    if state["version"] == 3:
        res = _load_state_v3(state)
    elif state["version"] == 4:
        res = _load_state_v4(state)
    else:
        raise TypeError("Unsupported version of state")
    _tf_cache[state_file] = res
    return res

