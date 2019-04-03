
"""Useful functions and classes for Python command-line tools.
"""

import sys
import inspect
import logging
import logging.config
import logging.handlers
import argparse

from vmtool.config import Config

__all__ = ['EnvScript', 'UsageError']


class UsageError(Exception):
    """User induced error."""


#
# logging setup
#

_log_config_done = 0
_log_init_done = {}


class EnvScript(object):
    """Loads environment-specific configuration.
    """

    service_name = None
    job_name = None
    cf = None
    cf_defaults = {}

    # setup logger here, this allows override by subclass
    log = logging.getLogger('EnvScript')

    def __init__(self, service_name, args):
        """Script setup.

        User class should override work() and optionally __init__(), startup(),
        reload(), reset(), shutdown() and init_optparse().

        NB: In case of daemon, __init__() and startup()/work()/shutdown() will be
        run in different processes.  So nothing fancy should be done in __init__().

        @param service_name: unique name for script.
            It will be also default job_name, if not specified in config.
        @param args: cmdline args (sys.argv[1:]), but can be overridden
        """
        self.service_name = service_name
        self.need_reload = 0
        self.exception_count = 0
        self.stat_dict = {}
        self.log_level = logging.INFO

        # parse command line
        parser = self.init_argparse()
        self.options = parser.parse_args(args)
        self.args = self.options.args

        # check args
        if self.options.version:
            #self.print_version()
            sys.exit(0)
        if self.options.quiet:
            self.log_level = logging.WARNING
        if self.options.verbose:
            self.log_level = logging.DEBUG

        # init logging
        logging.basicConfig(level=self.log_level,
                            format="%(asctime)s %(name)s - %(levelname)s: %(message)s",
                            datefmt="%H:%M:%S")

        self.cf_override = {}
        if self.options.set:
            for a in self.options.set:
                k, v = a.split('=', 1)
                self.cf_override[k.strip()] = v.strip()

        # read config file
        self.reload()

    def init_argparse(self, parser=None):
        """Initialize a ArgumentParser() instance that will be used to
        parse command line arguments.

        Note that it can be overridden both directions - either EnvScript
        will initialize an instance and pass it to user code or user can
        initialize and then pass to EnvScript.init_argparse().

        @param parser: optional ArgumentParser() instance,
               where EnvScript should attach its own arguments.
        @return: initialized OptionParser() instance.
        """
        if parser:
            p = parser
        else:
            p = argparse.ArgumentParser()

        # generic options
        p.add_argument("-q", "--quiet", action="store_true",
                       help="log only errors and warnings")
        p.add_argument("-v", "--verbose", action="count",
                       help="log verbosely")
        p.add_argument("-V", "--version", action="store_true",
                       help="print version info and exit")
        p.add_argument("--set", action="append",
                       help="override config setting (--set 'PARAM=VAL')")
        p.add_argument("command", help="command name")
        p.add_argument("args", nargs=argparse.REMAINDER, help="arguments for command")
        return p

    def reload(self):
        """Reload config.
        """
        self.log.debug('reload')
        # avoid double loading on startup
        if not self.cf:
            self.cf = self.load_config()
        else:
            self.cf.reload()
            self.log.info("Config reloaded")

    def startup(self):
        pass

    def reset(self):
        pass

    def start(self):
        self.run_func_safely(self.startup)
        self.run_func_safely(self.work, True)

    def run_func_safely(self, func, prefer_looping=False):
        "Run users work function, safely."
        try:
            return func()
        except UsageError as d:
            self.log.error(str(d))
        except MemoryError as d:
            try:    # complex logging may not succeed
                self.log.exception("Job %s out of memory, exiting", self.job_name)
            except MemoryError:
                self.log.fatal("Out of memory")
        except SystemExit as d:
            raise d
        except KeyboardInterrupt as d:
            sys.exit(1)
        except Exception as d:
            self.log.exception('Command failed')
        # done
        sys.exit(1)

    def load_config(self):
        """Loads config.
        """
        fn = self.options.command
        return Config(self.service_name, fn, user_defs=self.cf_defaults, override=self.cf_override)

    def work(self):
        """Non-looping work function, calls command function."""

        cmd = self.options.command
        cmdargs = self.options.args

        # find function
        fname = "cmd_" + cmd.replace('-', '_')
        if not hasattr(self, fname):
            self.log.error('bad subcommand, see --help for usage')
            sys.exit(1)
        fn = getattr(self, fname)

        # check if correct number of arguments
        (args, varargs, varkw, defaults, kwonlyargs, kwonlydefaults, annotations) = inspect.getfullargspec(fn)
        n_args = len(args) - 1   # drop 'self'
        if varargs is None and n_args != len(cmdargs):
            helpstr = ""
            if n_args:
                helpstr = ": " + " ".join(args[1:])
            self.log.error("command '%s' got %d args, but expects %d%s",
                           cmd, len(cmdargs), n_args, helpstr)
            sys.exit(1)

        # run command
        fn(*cmdargs)

