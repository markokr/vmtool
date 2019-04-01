"""VMTool profiles.
"""

import os
import sys

from configparser import ConfigParser
from vmtool.config import Config, AdvancedInterpolation

__all__ = ['load_env', 'load_env_config']


def find_gittop():
    vmlib = 'vmlib/runner.sh'
    pos = os.getcwd()
    while pos != '/':
        if os.path.isdir(os.path.join(pos, '.git')):
            if os.path.isfile(os.path.join(pos, vmlib)):
                return pos
        pos = os.path.normpath(os.path.join(pos, '..'))

    print("Need to be in repo that contains vmtool config")
    sys.exit(1)


def load_env(args):
    env_name = None
    role_name = None
    for a in args:
        if a[0] != '-':
            break
        elif a.startswith('--env'):
            tmp = a.split('=', 1)
            if len(tmp) != 2:
                print("Cannot parse --env arg")
                sys.exit(1)
            env_name = tmp[1]
        elif a.startswith('--role'):
            tmp = a.split('=', 1)
            if len(tmp) != 2:
                print("Cannot parse --role arg")
                sys.exit(1)
            role_name = tmp[1]
    if not env_name:
        env_name = os.environ.get('VMTOOL_ENV_NAME')
        if not env_name:
            print("Need to use --env or set VMTOOL_ENV_NAME")
            sys.exit(1)

    if role_name:
        return env_name.split('.')[0] + '.' + role_name
    return env_name


def load_deps(section_name, fn, defs, seen_files):
    basedir = os.path.dirname(fn)
    cf = ConfigParser(interpolation=AdvancedInterpolation())
    cf.read([fn])
    if cf.has_option(section_name, 'config_depends'):
        deps = cf.get(section_name, 'config_depends')
        for dep_fn in deps.split(','):
            dep_fn = dep_fn.strip()
            if not dep_fn:
                continue
            fqfn = os.path.normpath(os.path.join(basedir, dep_fn))
            if fqfn not in seen_files:
                if not os.path.isfile(fqfn):
                    raise IOError('load_deps: config missing: %s' % dep_fn)

                seen_files.add(fqfn)

                for sub in load_deps(section_name, fqfn, defs, seen_files):
                    yield sub

                yield fqfn


def load_env_config(env_name, func_map=None):
    if not env_name:
        raise Exception('load_env_config: env missing')
    git_dir = find_gittop()
    conf_dir = os.path.join(git_dir, 'conf')

    vmcf_fn = os.path.join(conf_dir, "config_%s.ini" % env_name)
    if not os.path.isfile(vmcf_fn):
        print("Config not found: %s" % vmcf_fn)
        sys.exit(1)

    for k in ('VMTOOL_USERNAME', 'USER', 'LOGNAME'):
        fl_user = os.environ.get(k)
        if fl_user:
            break
    if not fl_user:
        fl_user = 'please_set_VMTOOL_USERNAME'

    role_name = ''
    if '.' in env_name:
        env_name, role_name = env_name.split('.')

    defs = {
        'env_name': env_name,
        'role_name': role_name,
        'git_dir': git_dir,
        'conf_dir': conf_dir,
        'user': fl_user,
    }

    main_section = 'vm-config'

    deps = list(load_deps(main_section, vmcf_fn, defs, set()))
    deps.append(vmcf_fn)
    #print("Loading configs: %r" % deps)

    cf = Config(main_section, vmcf_fn, defs, func_map=func_map)
    for fqfn in deps:
        if not os.path.isfile(fqfn):
            print("Config not found: %s" % fqfn)
            sys.exit(1)
        cf.cf.read([fqfn])

    return cf

