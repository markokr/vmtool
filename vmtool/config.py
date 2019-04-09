
"""Nicer config class."""

import os
import os.path
import re
import socket

from configparser import (
    NoOptionError, NoSectionError, InterpolationError, InterpolationDepthError, InterpolationSyntaxError,
    Error as ConfigError, ConfigParser, MAX_INTERPOLATION_DEPTH,
    Interpolation)


__all__ = ['Config', 'NoOptionError', 'ConfigError', 'AdvancedInterpolation']

_UNSET = object()

class Config(object):
    """Bit improved ConfigParser.

    Additional features:
     - Remembers section.
     - Accepts defaults in get() functions.
     - List value support.
    """
    def __init__(self, main_section, filename, user_defs=None, override=None, ignore_defs=False, func_map=None):
        """Initialize Config and read from file.
        """
        # use config file name as default job_name
        if filename:
            job_name = os.path.splitext(os.path.basename(filename))[0]
        else:
            job_name = main_section

        # initialize defaults, make them usable in config file
        if ignore_defs:
            self.defs = {}
        else:
            self.defs = {
                'job_name': job_name,
                'service_name': main_section,
                'host_name': socket.gethostname(),
            }
            if filename:
                self.defs['config_dir'] = os.path.dirname(filename)
                self.defs['config_file'] = filename
            if user_defs:
                self.defs.update(user_defs)

        self.main_section = main_section
        self.filename = filename
        self.override = override or {}
        self.cf = ConfigParser(interpolation=AdvancedInterpolation(func_map=func_map))

        if filename is None:
            self.cf.add_section(main_section)
        elif not os.path.isfile(filename):
            raise ConfigError('Config file not found: ' + filename)

        self.reload()

    def reload(self):
        """Re-reads config file."""
        if self.filename:
            self.cf.read(self.filename)
        if not self.cf.has_section(self.main_section):
            raise NoSectionError(self.main_section)

        # apply default if key not set
        for k, v in self.defs.items():
            if not self.cf.has_option(self.main_section, k):
                self.cf.set(self.main_section, k, v)

        # apply overrides
        if self.override:
            for k, v in self.override.items():
                self.cf.set(self.main_section, k, v)

    def get(self, key, default=_UNSET):
        """Reads string value, if not set then default."""

        if not self.cf.has_option(self.main_section, key):
            if default is _UNSET:
                raise NoOptionError(key, self.main_section)
            return default

        return str(self.cf.get(self.main_section, key))

    def getint(self, key, default=_UNSET):
        """Reads int value, if not set then default."""

        if not self.cf.has_option(self.main_section, key):
            if default is _UNSET:
                raise NoOptionError(key, self.main_section)
            return default

        return self.cf.getint(self.main_section, key)

    def getboolean(self, key, default=_UNSET):
        """Reads boolean value, if not set then default."""

        if not self.cf.has_option(self.main_section, key):
            if default is _UNSET:
                raise NoOptionError(key, self.main_section)
            return default

        return self.cf.getboolean(self.main_section, key)

    def getfloat(self, key, default=_UNSET):
        """Reads float value, if not set then default."""

        if not self.cf.has_option(self.main_section, key):
            if default is _UNSET:
                raise NoOptionError(key, self.main_section)
            return default

        return self.cf.getfloat(self.main_section, key)

    def getlist(self, key, default=_UNSET):
        """Reads comma-separated list from key."""

        if not self.cf.has_option(self.main_section, key):
            if default is _UNSET:
                raise NoOptionError(key, self.main_section)
            return default

        s = self.get(key).strip()
        res = []
        if not s:
            return res
        for v in s.split(","):
            v = v.strip()
            if v:
                res.append(v)
        return res

    def getdict(self, key, default=_UNSET):
        """Reads key-value dict from parameter.

        Key and value are separated with ':'.  If missing,
        key itself is taken as value.
        """

        if not self.cf.has_option(self.main_section, key):
            if default is _UNSET:
                raise NoOptionError(key, self.main_section)
            return default

        s = self.get(key).strip()
        res = {}
        if not s:
            return res
        for kv in s.split(","):
            tmp = kv.split(':', 1)
            if len(tmp) > 1:
                k = tmp[0].strip()
                v = tmp[1].strip()
            else:
                k = kv.strip()
                v = k
            res[k] = v
        return res

    def getfile(self, key, default=_UNSET):
        """Reads filename from config.

        In addition to reading string value, expands ~ to user directory.
        """
        fn = self.get(key, default)
        if fn == "" or fn == "-":
            return fn
        fn = os.path.expanduser(fn)
        return fn

    def sections(self):
        """Returns list of sections in config file, excluding DEFAULT."""
        return self.cf.sections()

    def has_section(self, section):
        """Checks if section is present in config file, excluding DEFAULT."""
        return self.cf.has_section(section)

    def clone(self, main_section):
        """Return new Config() instance with new main section on same config file."""
        return Config(main_section, self.filename)

    def options(self):
        """Return list of options in main section."""
        return self.cf.options(self.main_section)

    def has_option(self, opt):
        """Checks if option exists in main section."""
        return self.cf.has_option(self.main_section, opt)

    def items(self):
        """Returns list of (name, value) for each option in main section."""
        return self.cf.items(self.main_section)

    def set(self, key, val):
        """Sets key value.
        """
        self.cf.set(self.main_section, key, val)

    def view_section(self, section):
        cf = Config(section, None)
        cf.cf = self.cf
        return cf


_NEW_VAR_OPEN_RX = re.compile(r'\$\$|\$\{')
_NEW_VAR_BOTH_RX = re.compile(r'\$\$|\$\{|}')


def _scan_key(cur_sect, cur_key, value, pos, lookup_func):
    dst = []
    while 1:
        m = _NEW_VAR_BOTH_RX.search(value, pos)
        if not m:
            raise Exception('Closing brace not found')
        pos2 = m.start()
        if pos2 > pos:
            dst.append(value[pos:pos2])
        pos = m.end()
        tok = m.group(0)
        if tok == '}':
            subkey = ''.join(dst)
            subval = lookup_func(cur_sect, subkey)
            return subval, pos
        elif tok == '$$':
            dst.append('$')
        elif tok == '${':
            subval, pos = _scan_key(cur_sect, cur_key, value, pos, lookup_func)
            dst.append(subval)
        else:
            break
    raise Exception('bad token')


def new_interpolate(cur_sect, cur_key, value, lookup_func):
    """Recursive interp

    >>> lookup = lambda s, x: '<'+x+'>'
    >>> new_interpolate('sect', 'key', 'text', lookup)
    'text'
    >>> new_interpolate('sect', 'key', 'foo.${baz}.com', lookup)
    'foo.<baz>.com'
    >>> new_interpolate('sect', 'key', 'foo.${baz.${goo}.zap}.com', lookup)
    'foo.<baz.<goo>.zap>.com'
    """
    if not value:
        return value

    pos = 0
    dst = []
    while pos < len(value):
        m = _NEW_VAR_OPEN_RX.search(value, pos)
        if not m:
            dst.append(value[pos:])
            break
        pos2 = m.start()
        if pos2 > pos:
            dst.append(value[pos:pos2])
        pos = m.end()
        tok = m.group(0)
        if tok == '$$':
            dst.append('$')
        elif tok == '${':
            subval, pos = _scan_key(cur_sect, cur_key, value, pos, lookup_func)
            dst.append(subval)
        else:
            raise InterpolationSyntaxError(cur_key, cur_sect, 'Interpolation parse error')
    return ''.join(dst)


class AdvancedInterpolation(Interpolation):
    _func_map = None

    def __init__(self, func_map=None):
        super(AdvancedInterpolation, self).__init__()
        self._func_map = func_map

    def before_get(self, parser, section, option, value, defaults):
        dst = []
        self._interpolate_ext_new(dst, parser, section, option, value, defaults, set())
        return ''.join(dst)

    def before_set(self, parser, section, option, value):
        # cannot validate complex interpolation with regex
        return value

    def _interpolate_ext_new(self, dst, parser, section, option, rawval, defaults, loop_detect):
        if not rawval:
            return rawval

        if len(loop_detect) > MAX_INTERPOLATION_DEPTH:
            raise InterpolationDepthError(option, section, rawval)

        xloop = (section, option)
        if xloop in loop_detect:
            raise InterpolationError(option, section, 'Loop detected: %r in %r' % (xloop, loop_detect))
        loop_detect.add(xloop)

        def lookup_helper(lk_section, lk_option):
            if '!' in lk_option:
                funcname, val = lk_option.split('!', 1)
                func = None
                if self._func_map:
                    func = self._func_map.get(funcname.strip())
                if not func:
                    raise InterpolationError(option, section, 'Unknown interpolation function: %r' % funcname)
                return func(val.strip(), lk_section, lk_option)

            # normal fetch
            if ':' in lk_option:
                ksect, key = lk_option.split(':', 1)
                ksect, key = ksect.strip(), key.strip()
                use_vars = None
            else:
                ksect, key = lk_section, lk_option.strip()
                use_vars = defaults
            key = parser.optionxform(key)
            newpart = parser.get(ksect, key, raw=True, vars=use_vars)
            if newpart is None:
                raise InterpolationError(key, ksect, 'Key referenced is None')
            dst = []
            self._interpolate_ext_new(dst, parser, ksect, key, newpart, defaults, loop_detect)
            return ''.join(dst)

        val = new_interpolate(section, option, rawval, lookup_helper)
        dst.append(val)
        loop_detect.remove(xloop)

