#! /usr/bin/env python3

"""vmtool.py <command> <command args>

    Tool for managing AWS instances.
"""

import sys
import importlib
import shlex

from vmtool.envconfig import load_env, load_env_config


def run_command(cf, args):
    """Command is implemented by class specified in vmtool_profile.
    """
    mod_name = cf.get('vmtool_profile')
    mod = importlib.import_module(mod_name)

    script = mod.VmTool('vmtool', args)
    script.start()
    sys.stdout.flush()
    sys.stderr.flush()


def run_alias(env_name, alias, cmd, cmdpos, args, options, is_cmd):
    """Alias that launches different other commands.

    It cannot launch other aliases.

    Example - run "foo" on role "this" and "foox" on "other"::

        [alias.foo]
        roles = this, other:foox

    Example - run "foo" on current role and "foox" on "other"::

        [alias.foo]
        commands = foo, other:foox

    """
    cmd_prefix = args[:cmdpos]
    cmd_self = args[cmdpos:cmdpos+1]
    cmd_suffix = args[cmdpos+1:]
    for elem in alias.split(','):
        elem = elem.strip()
        if ':' in elem:
            role, acmd = elem.split(':', 1)
            role, acmd = role.strip(), acmd.strip()
            xcmd = shlex.split(acmd)
        elif is_cmd:
            xcmd = shlex.split(elem)
            role = None
        else:
            xcmd = cmd_self
            role = elem

        xargs = cmd_prefix + xcmd + cmd_suffix
        if role:
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
    """Parse command-line, run commands.
    """
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
        if cf.cf.has_option(alias_sect, 'roles'):
            alias = cf.cf.get(alias_sect, 'roles')
            is_cmd = False
        else:
            alias = cf.cf.get(alias_sect, 'commands')
            is_cmd = True
        options = []
        if cf.cf.has_option(alias_sect, 'options'):
            options = shlex.split(cf.cf.get(alias_sect, 'options'))
        run_alias(env_name, alias, cmd, cmdpos, args, options, is_cmd)
    else:
        run_command(cf, args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

