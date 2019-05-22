#! /usr/bin/env python3

"""vmtool.py <command> <command args>

    Tool for managing AWS instances.
"""

import sys
import importlib

from vmtool.envconfig import load_env, load_env_config


def run_command(cf, args):
    mod_name = cf.get('vmtool_profile')
    mod = importlib.import_module(mod_name)
    script = mod.VmTool('vmtool', args)
    script.start()
    sys.stdout.flush()
    sys.stderr.flush()


def run_alias(env_name, alias, cmd, cmdpos, args, options):
    for role in alias.split(','):
        role = role.strip()
        xargs = args[:]
        xcmd = cmd
        if ':' in role:
            role, xcmd = role.split(':')
            role, xcmd = role.strip(), xcmd.strip()
            xargs[cmdpos] = xcmd
        xargs = ['--role=' + role] + xargs

        extra = ''
        if options:
            extra = ' [%s]' % ' '.join(options)
            xargs = options + xargs
        env_name = load_env(xargs)

        sys.stderr.write("%s: running '%s' at %s%s\n" % (cmd, xcmd, env_name, extra))

        cf = load_env_config(env_name)
        run_command(cf, xargs)


def main():
    args = sys.argv[1:]
    # parse command
    cmd = None
    cmdpos = None
    for i, a in enumerate(args):
        if cmd is None:
            if a[0] != '-':
                cmd = a
                cmdpos = i
        elif a[0] == '-':
            args.insert(cmdpos + 1, '--')
            break

    # load config
    env_name = load_env(args)
    cf = load_env_config(env_name)

    # does role need replacing
    alias_sect = 'alias.%s' % cmd
    if cmd and cf.has_section(alias_sect):
        alias = cf.cf.get(alias_sect, 'roles')
        options = []
        if cf.cf.has_option(alias_sect, 'options'):
            options = cf.cf.get(alias_sect, 'options').split()
        run_alias(env_name, alias, cmd, cmdpos, args, options)
    else:
        run_command(cf, args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

