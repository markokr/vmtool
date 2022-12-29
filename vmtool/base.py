"""Common logic.
"""

import argparse
import binascii
import enum
import fnmatch
import ipaddress
import logging
import os.path
import re
import shlex
import stat
import subprocess
import sys
import uuid

from vmtool.certs import load_cert_config
from vmtool.config import Config, NoOptionError
from vmtool.envconfig import find_gittop, load_env_config
from vmtool.scripting import EnvScript, UsageError
from vmtool.tarfilter import TarFilter
from vmtool.terra import tf_load_output_var
from vmtool.util import (
    as_unicode, eprintf, local_cmd, printf,
    rsh_quote, run_successfully, time_printf,
)
from vmtool.xglob import xglob

SSH_USER_CREATION = """\
if ! grep -q '^{user}:' /etc/passwd; then
  echo "Adding user {user}"
  adduser -q --gecos {user} --disabled-password {user} < /dev/null
  install -d -o {user} -g {user} -m 700  ~{user}/.ssh
  echo "{pubkey}" > ~{user}/.ssh/authorized_keys
  chmod 600 ~{user}/.ssh/authorized_keys
  chown {user}:{user} ~{user}/.ssh/authorized_keys
  for grp in {auth_groups}; do
    adduser -q {user} $grp
  done
fi
"""


def mk_sshuser_script(user, auth_groups, pubkey):
    return SSH_USER_CREATION.format(user=user, auth_groups=" ".join(auth_groups), pubkey=pubkey)


class VmCmd(enum.Enum):
    """Sub-command names used internally in vmtool.
    """
    PREP = "prep"
    FAILOVER_PROMOTE_SECONDARY = "failover_promote_secondary"

    TAKEOVER_PREPARE_PRIMARY = "takeover_prepare_primary"
    TAKEOVER_PREPARE_SECONDARY = "takeover_prepare_secondary"
    TAKEOVER_FINISH_PRIMARY = "takeover_finish_primary"
    TAKEOVER_FINISH_SECONDARY = "takeover_finish_secondary"

    DROP_NODE_PREPARE = "drop_node_prepare"


class VmToolBase(EnvScript):
    # replace those with root specified by image
    ROOT_DEV_NAMES = ("root",)

    log = logging.getLogger("vmtool")

    role_name = None
    env_name = None     # name of current env
    full_role = None
    ssh_dir = None
    git_dir = None
    keys_dir = None
    is_live = False
    availability_zone = None
    ssh_known_hosts = None

    new_commit = None
    old_commit = None

    def init_argparse(self, parser=None):
        if parser is None:
            parser = argparse.ArgumentParser(prog="vmtool")
        p = super().init_argparse(parser)
        #doc = self.__doc__.strip()
        #p.set_usage(doc)
        p.add_argument("--env", help="Set environment name (default comes from VMTOOL_ENV_NAME)")
        p.add_argument("--role", help="Set role name (default: None)")
        p.add_argument("--host", help="Use host instead detecting")
        p.add_argument("--all", action="store_true", help="Make command work over all envs")
        p.add_argument("--ssh-key", help="Use different SSH key")
        p.add_argument("--all-role-vms", action="store_true", help="Run command on all vms for role")
        p.add_argument("--all-role-fo-vms", action="store_true", help="Run command on all failover vms for role")
        p.add_argument("--earlier-fo-vms", action="store_true", help="Run command on earlier failover vms for role")
        p.add_argument("--latest-fo-vm", action="store_true", help="Run command on latest failover vm for rolw")
        p.add_argument("--running", action="store_true", help="Show only running instances")
        p.add_argument("--az", type=int, help="Set availability zone")
        p.add_argument("--tmux", action="store_true", help="Wrap session in tmux")
        return p

    def reload(self):
        """Reload config.
        """
        self.git_dir = find_gittop()

        # ~/.vmtool
        ssh_dir = os.path.expanduser("~/.vmtool")
        if not os.path.isdir(ssh_dir):
            os.mkdir(ssh_dir, stat.S_IRWXU)

        keys_dir = os.environ.get("VMTOOL_KEY_DIR", os.path.join(self.git_dir, "keys"))
        if not keys_dir or not os.path.isdir(keys_dir):
            raise UsageError("Set vmtool config dir: VMTOOL_KEY_DIR")

        ca_log_dir = os.environ.get("VMTOOL_CA_LOG_DIR")
        if not ca_log_dir or not os.path.isdir(ca_log_dir):
            raise UsageError("Set vmtool config dir: VMTOOL_CA_LOG_DIR")

        env = os.environ.get("VMTOOL_ENV_NAME", "")
        if self.options.env:
            env = self.options.env
        if not env:
            raise UsageError("No envronment set: either set VMTOOL_ENV_NAME or give --env=ENV")

        env_name = env
        self.full_role = env
        if "." in env:
            env_name, self.role_name = env.split(".")
        self.env_name = env_name
        if self.options.role:
            self.role_name = self.options.role
            self.full_role = "%s.%s" % (self.env_name, self.role_name)

        self.ca_log_dir = ca_log_dir
        self.keys_dir = keys_dir
        self.ssh_dir = ssh_dir

        self.cf = load_env_config(self.full_role, {
            "FILE": self.conf_func_file,
            "KEY": self.conf_func_key,
            "TF": self.conf_func_tf,
            "TFAZ": self.conf_func_tfaz,
            "PRIMARY_VM": self.conf_func_primary_vm,
            "NETWORK": self.conf_func_network,
            "NETMASK": self.conf_func_netmask,
            "MEMBERS": self.conf_func_members,
        })
        self.process_pkgs()

        self._region = self.cf.get("region")
        self.ssh_known_hosts = os.path.join(self.ssh_dir, "known_hosts")
        self.is_live = self.cf.getint("is_live", 0)

        if self.options.az is not None:
            self.availability_zone = self.options.az
        else:
            self.availability_zone = self.cf.getint("availability_zone", 0)

        # fill vm_ordered_disk_names
        disk_map = self.get_disk_map()
        if disk_map:
            api_order = []
            size_order = []
            for dev in disk_map:
                size = disk_map[dev]["size"]
                count = disk_map[dev]["count"]
                if size and dev not in self.ROOT_DEV_NAMES:
                    for i in range(count):
                        name = f"{dev}.{i}" if count > 1 else dev
                        size_order.append((size, i, name))
                        api_order.append(name)
            size_order.sort()
            self.cf.set("vm_disk_names_size_order", ", ".join([elem[2] for elem in size_order]))
            self.cf.set("vm_disk_names_api_order", ", ".join(api_order))

    def get_disk_map(self):
        """Parse disk_map option.
        """
        disk_map = self.cf.getdict("disk_map", {})
        if not disk_map:
            disk_map = {"root": "size=12"}

        res_map = {}
        for dev in disk_map:
            val = disk_map[dev]
            local = {}
            for opt in val.split(":"):
                if "=" in opt:
                    k, v = opt.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                else:
                    k = v = opt.strip()
                    if not k:
                        continue
                    if k.startswith("ephemeral"):
                        k = "ephemeral"
                if k in ("size", "count", "iops", "throughput"):
                    v = int(v)
                local[k] = v
            if "count" not in local:
                local["count"] = 1
            if "size" not in local:
                raise UsageError("Each element in disk_map needs size")
            res_map[dev] = local

        # sanity check if requested
        disk_require_order = self.cf.getlist("disk_require_order", [])
        if disk_require_order:
            # order from disk_map
            got_order = sorted([
                (res_map[name]["size"], res_map[name]["count"], name)
                for name in res_map
            ])
            names_order = [f"{name}:{count}" for size, count, name in got_order]

            # order from disk_require_order
            counted_order = [
                key if ":" in key else key + ":1"
                for key in disk_require_order
            ]

            if names_order != counted_order:
                raise UsageError("Order mismatch:\n  require=%r\n  got=%r" % (counted_order, names_order))

        return res_map

    _gpg_cache = None
    def load_gpg_file(self, fn):
        if self._gpg_cache is None:
            self._gpg_cache = {}
        if fn in self._gpg_cache:
            return self._gpg_cache[fn]
        if self.options.verbose:
            printf("GPG: %s", fn)
        # file data directly
        if not os.path.isfile(fn):
            raise UsageError("GPG file not found: %s" % fn)
        data = self.popen(["gpg", "-q", "-d", "--batch", fn])
        res = as_unicode(data)
        self._gpg_cache[fn] = res
        return res

    def load_gpg_config(self, fn, main_section):
        realfn = os.path.join(self.keys_dir, fn)
        if not os.path.isfile(realfn):
            raise UsageError("GPG file not found: %s" % realfn)
        data = self.load_gpg_file(realfn)
        cf = Config(main_section, None)
        cf.cf.read_string(data, source=realfn)
        return cf

    def popen(self, cmd, input_data=None, **kwargs):
        """Read command stdout, check for exit code.
        """
        pipes = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        if input_data is not None:
            pipes["stdin"] = subprocess.PIPE
        with subprocess.Popen(cmd, **kwargs, **pipes) as p:
            out, err = p.communicate(input_data)
            if p.returncode != 0:
                raise Exception("command failed: %r - %r" % (cmd, err.strip()))
        return out

    def load_command_docs(self):
        doc = self.__doc__.strip()
        doc = ""
        grc = re.compile(r"Group: *(\w+)")
        cmds = []

        for fn in sorted(dir(self)):
            if fn.startswith("cmd_"):
                fobj = getattr(self, fn)
                docstr = (getattr(fobj, "__doc__", "") or "").strip()
                mgrp = grc.search(docstr)
                grpname = mgrp and mgrp.group(1) or ""
                lines = docstr.split("\n")
                fdoc = lines[0]
                cmd = fn[4:].replace("_", "-")
                cmds.append((grpname, cmd, fdoc))

        for sect in self.cf.sections():
            if sect.startswith("cmd.") or sect.startswith("alias."):
                cmd = sect.split(".", 1)[1]
                desc = ""
                grpname = ""
                if self.cf.cf.has_option(sect, "desc"):
                    desc = self.cf.cf.get(sect, "desc")
                if self.cf.cf.has_option(sect, "group"):
                    grpname = self.cf.cf.get(sect, "group")
                fdoc = desc.strip().split("\n")[0]
                cmds.append((grpname, cmd, desc))

        cmds.sort()
        last_grp = None
        sep = ""
        for grpname, cmd, fdoc in cmds:
            if grpname != last_grp:
                doc += sep + "%s commands:\n" % (grpname or "ungrouped")
                last_grp = grpname
                sep = "\n"
            doc += "  %-30s - %s\n" % (cmd, fdoc)
        return doc

    def cmd_help(self):
        """Show help about commands.

        Group: info
        """
        doc = self.load_command_docs()
        printf(doc)

    def filter_key_lookup(self, predef, key, fname):
        if key in predef:
            return predef[key]

        if key == "MASTER_KEYS":
            master_key_list = []
            nr = 1
            while True:
                kname = "master_key_%d" % nr
                v = self.cf.get(kname, "")
                if not v:
                    break
                master_key_list.append("%s = %s" % (kname, v))
                nr += 1
            if not master_key_list:
                raise Exception("No master keys found")
            master_key_conf = "\n".join(master_key_list)
            return master_key_conf

        if key == "SYSRANDOM":
            blk = os.urandom(3 * 16)
            b64 = binascii.b2a_base64(blk).strip()
            return b64.decode("utf8")

        if key == "AUTHORIZED_KEYS":
            auth_users = self.cf.getlist("ssh_authorized_users", [])
            pat = self.cf.get("ssh_pubkey_pattern")
            keys = []
            for user in sorted(set(auth_users)):
                fn = os.path.join(self.keys_dir, pat.replace("USER", user))
                with open(fn, "r", encoding="utf8") as f:
                    pubkey = f.read().strip()
                keys.append(pubkey)
            return "\n".join(keys)

        if key == "AUTHORIZED_USER_CREATION":
            return self.make_user_creation()

        try:
            return self.cf.get(key)
        except NoOptionError:
            raise UsageError("%s: key not found: %s" % (fname, key)) from None

    def make_user_creation(self):
        auth_groups = self.cf.getlist("authorized_user_groups", [])
        auth_users = self.cf.getlist("ssh_authorized_users", [])
        pat = self.cf.get("ssh_pubkey_pattern")
        script = []
        for user in sorted(set(auth_users)):
            fn = os.path.join(self.keys_dir, pat.replace("USER", user))
            with open(fn, encoding="utf8") as f:
                pubkey = f.read().strip()
            script.append(mk_sshuser_script(user, auth_groups, pubkey))
        return "\n".join(script)

    def make_tar_filter(self, extra_defs=None):
        defs = {}
        if extra_defs:
            defs.update(extra_defs)
        tb = TarFilter(self.filter_key_lookup, defs)
        tb.set_live(self.is_live)
        return tb

    def conf_func_file(self, arg, sect, kname):
        """Returns contents of file, optionally gpg-decrypted.

        Usage: ${FILE ! filename}
        """
        if self.options.verbose:
            printf("FILE: %s", arg)
        fn = os.path.join(self.keys_dir, arg)
        if not os.path.isfile(fn):
            raise UsageError("%s - FILE missing: %s" % (kname, arg))
        if fn.endswith(".gpg"):
            return self.load_gpg_file(fn).rstrip("\n")
        with open(fn, "r", encoding="utf8") as f:
            return f.read().rstrip("\n")

    def conf_func_key(self, arg, sect, kname):
        """Returns key from Terraform state file.

        Usage: ${KEY ! fn : key}
        """
        bfn, subkey = arg.split(":")
        if self.options.verbose:
            printf("KEY: %s : %s", bfn.strip(), subkey.strip())
        fn = os.path.join(self.keys_dir, bfn.strip())
        if not os.path.isfile(fn):
            raise UsageError("%s - KEY file missing: %s" % (kname, fn))
        cf = self.load_gpg_config(fn, "vm-config")
        subkey = as_unicode(subkey.strip())
        try:
            return cf.get(subkey)
        except BaseException:
            raise UsageError("%s - Key '%s' unset in '%s'" % (kname, subkey, fn)) from None

    def conf_func_tf(self, arg, sect, kname):
        """Returns key from Terraform state file.

        Usage: ${TF ! tfvar}
        """
        if ":" in arg:
            state_file, arg = [s.strip() for s in arg.split(":", 1)]
        else:
            state_file = self.cf.get("tf_state_file")
        val = tf_load_output_var(state_file, arg)

        # configparser expects strings
        if isinstance(val, str):
            # work around tf dots in route53 data
            val = val.strip().rstrip(".")
        elif isinstance(val, int):
            val = str(val)
        elif isinstance(val, float):
            val = repr(val)
        elif isinstance(val, bool):
            val = str(val).lower()
        else:
            raise UsageError("TF function got invalid type: %s - %s" % (kname, type(val)))
        return val

    def conf_func_members(self, arg, sect, kname):
        """Returns field that match patters.

        Usage: ${MEMBERS ! pat : fn : field}
        """
        pats, bfn, field = arg.split(":")
        fn = os.path.join(self.keys_dir, bfn.strip())
        if not os.path.isfile(fn):
            raise UsageError("%s - MEMBERS file missing: %s" % (kname, fn))

        idx = int(field, 10)

        findLabels = []
        for p in pats.split(","):
            p = p.strip()
            if p:
                findLabels.append(p)

        res = []
        with open(fn, "r", encoding="utf8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln[0] == "#":
                    continue
                got = False
                parts = ln.split(":")
                user = parts[0].strip()
                for label in parts[idx].split(","):
                    label = label.strip()
                    if label and label in findLabels:
                        got = True
                        break
                if got and user not in res:
                    res.append(user)

        return ", ".join(res)

    def conf_func_tfaz(self, arg, sect, kname):
        """Returns key from Terraform state file.

        Usage: ${TFAZ ! tfvar}
        """
        if self.options.verbose:
            printf("TFAZ: %s", arg)
        if ":" in arg:
            state_file, arg = [s.strip() for s in arg.split(":", 1)]
        else:
            state_file = self.cf.get("tf_state_file")
        val = tf_load_output_var(state_file, arg)
        if not isinstance(val, list):
            raise UsageError("TFAZ function expects list param: %s" % kname)
        if self.availability_zone < 0 or self.availability_zone >= len(val):
            raise UsageError("AZ value out of range")
        return val[self.availability_zone]

    def conf_func_primary_vm(self, arg, sect, kname):
        """Lookup primary vm.

        Usage: ${PRIMARY_VM ! ${other_role}}
        """
        raise NotImplementedError

    def conf_func_network(self, arg, sect, kname):
        """Extract network address from CIDR.
        """
        return str(ipaddress.ip_network(arg).network_address)

    def conf_func_netmask(self, arg, sect, kname):
        """Extract 32-bit netmask from CIDR.
        """
        return str(ipaddress.ip_network(arg).netmask)

    def get_ssh_kfile(self):
        # load encrypted key
        if self.options.ssh_key:
            gpg_fn = self.options.ssh_key
        else:
            gpg_fn = self.cf.get("ssh_privkey_file")
        gpg_fn = os.path.join(self.keys_dir, gpg_fn)
        kdata = self.load_gpg_file(gpg_fn).strip()

        raw_fn = os.path.basename(gpg_fn).replace(".gpg", "")

        fn = os.path.join(self.ssh_dir, raw_fn)

        # check existing key
        if os.path.isfile(fn):
            with open(fn, "r", encoding="utf8") as f:
                curdata = f.read().strip()
            if curdata == kdata:
                return fn
            os.remove(fn)

        printf("Extracting keyfile %s to %s", gpg_fn, fn)
        fd = os.open(fn, os.O_CREAT | os.O_WRONLY, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(kdata + "\n")
        return fn

    def get_ssh_known_hosts_file(self, vm_id):
        return self.ssh_known_hosts + "_" + vm_id

    def ssh_cmdline(self, vm_id, use_admin=False, check_tty=False):
        if self.cf.getboolean("ssh_admin_user_disabled", False):
            ssh_user = self.cf.get("user")
        elif use_admin:
            ssh_user = self.cf.get("ssh_admin_user")
        else:
            ssh_user = self.cf.get("user")

        ssh_debug = "-q"
        if self.options.verbose:
            ssh_debug = "-v"

        ssh_options = shlex.split(self.cf.get("ssh_options", ""))

        if check_tty and sys.stdout.isatty():        # pylint:disable=no-member
            ssh_options.append("-t")

        return ["ssh", ssh_debug, "-i", self.get_ssh_kfile(), "-l", ssh_user,
                "-o", "UserKnownHostsFile=" + self.get_ssh_known_hosts_file(vm_id)] + ssh_options

    def vm_exec_tmux(self, vm_id, cmdline, use_admin=False, title=None):
        if self.options.tmux:
            tmux_command = shlex.split(self.cf.get("tmux_command"))
            if title:
                tmux_command = [a.replace("{title}", title) for a in tmux_command]
            cmdline = tmux_command + cmdline
        self.vm_exec(vm_id, cmdline, use_admin=use_admin)

    def vm_exec(self, vm_id, cmdline, stdin=None, get_output=False, check_error=True, use_admin=False):
        self.log.debug("EXEC@%s: %s", vm_id, cmdline)
        self.put_known_host_from_tags(vm_id)

        # only image default user works?
        if not self.cf.getboolean("ssh_user_access_works", False):
            use_admin = True

        if self.options.host:
            # use host directly, dangerous
            hostname = self.options.host
        elif self.cf.getboolean("ssh_internal_ip_works", False):
            vm = self.vm_lookup(vm_id)
            hostname = vm.get("PrivateIpAddress")
        else:
            # FIXME: vm with ENI
            vm = self.vm_lookup(vm_id)
            #hostname = vm.get("PublicDnsName")
            hostname = vm.get("PublicIpAddress")
            last_idx = 600 * 1024 * 1024 * 1024
            if len(vm["NetworkInterfaces"]) > 1:
                for iface in vm["NetworkInterfaces"]:
                    #print_json(iface)
                    idx = iface["Attachment"]["DeviceIndex"]
                    if 1 or idx < last_idx:
                        assoc = iface.get("Association")
                        if assoc:
                            hostname = assoc["PublicIp"]
                            last_idx = idx
                            break
                eprintf("SSH to %s", hostname)
        if not hostname:
            self.log.error("Public DNS nor ip not yet available for node %r", vm_id)
            #print_json(vm)
            sys.exit(1)

        check_tty = not stdin and not get_output
        ssh = self.ssh_cmdline(vm_id, use_admin=use_admin, check_tty=check_tty)
        ssh.append(hostname)
        if isinstance(cmdline, str):
            ssh += [cmdline]
        elif self.cf.getboolean("ssh_disable_quote", False):
            ssh += cmdline
        else:
            ssh += rsh_quote(cmdline)
        out = None
        kwargs = {}
        if stdin is not None:
            kwargs["stdin"] = subprocess.PIPE
        if get_output:
            kwargs["stdout"] = subprocess.PIPE
        self.log.debug("EXEC: cmd=%r", ssh)
        self.log.debug("EXEC: kwargs=%r", kwargs)
        if kwargs:
            with subprocess.Popen(ssh, **kwargs) as p:
                out, err = p.communicate(stdin)
                ret = p.returncode
        else:
            ret = subprocess.call(ssh)
        if ret != 0:
            if check_error:
                raise UsageError("Errorcode: %r" % ret)
            return None
        return out

    def vm_rsync(self, *args, use_admin=False):
        primary_id = None
        nargs = []
        ids = []
        vm_id = "?"
        for a in args:
            t = a.split(":", 1)
            if len(t) == 1:
                nargs.append(a)
                continue
            if t[0]:
                vm_id = t[0]
            elif primary_id:
                vm_id = primary_id
            else:
                vm_id = primary_id = self.get_primary_vms()[0]
            vm = self.vm_lookup(vm_id)
            self.put_known_host_from_tags(vm_id)
            vm = self.vm_lookup(vm_id)
            if self.cf.getboolean("ssh_internal_ip_works", False):
                hostname = vm.get("PrivateIpAddress")
            else:
                hostname = vm.get("PublicIpAddress")
            a = "%s:%s" % (hostname, t[1])
            nargs.append(a)
            ids.append(vm_id)

        ssh_list = self.ssh_cmdline(vm_id, use_admin=use_admin)
        ssh_cmd = " ".join(rsh_quote(ssh_list))

        cmd = ["rsync", "-rtz", "-e", ssh_cmd]
        if self.options.verbose:
            cmd.append("-P")
        cmd += nargs
        self.log.debug("rsync: %r", cmd)
        run_successfully(cmd)

    _PREP_TGZ_CACHE = {}    # cmd->tgz
    _PREP_STAMP_CACHE = {}  # cmd->stamp

    def cmd_mod_test(self, cmd_name):
        """Test if payload can be created for command.

        Group: internal
        """
        self.modcmd_init(cmd_name)
        data = self._PREP_TGZ_CACHE[cmd_name]
        print("Data size: %d bytes" % len(data))
        return data

    def cmd_mod_dump(self, cmd_name):
        """Write tarball of command payload.

        Group: internal
        """
        self.modcmd_init(cmd_name)
        data = self._PREP_TGZ_CACHE[cmd_name]
        fn = "data.tgz"
        with open(fn, "wb", encoding="utf8") as f:
            f.write(data)
        print("%s: %d bytes" % (fn, len(data)))

    def cmd_mod_show(self, cmd_name):
        """Show vmlibs used for command.

        Group: internal
        """
        cwd = self.git_dir
        os.chdir(cwd)

        cmd_cf = self.cf.view_section("cmd.%s" % cmd_name)

        vmlibs = cmd_cf.getlist("vmlibs")

        print("Included libs")
        got = set()
        for mod in vmlibs:
            if mod not in got:
                print("+ " + mod)
                got.add(mod)

        exc_libs = []
        for mod in xglob("vmlib/**/setup.sh"):
            mod = "/".join(mod.split("/")[1:-1])
            if mod not in got:
                exc_libs.append(mod)
        exc_libs.sort()

        print("Excluded libs")
        for mod in exc_libs:
            print("- " + mod)

    def has_modcmd(self, cmd_name: VmCmd):
        """Return true if command is configured from config.
        """
        return self.cf.has_section("cmd.%s" % cmd_name)

    def load_modcmd_args(self, args):
        vms = []
        for a in args:
            if a.startswith('i-'):
                vms.append(a)
            else:
                raise UsageError("command supports only vmid args")
        if vms:
            return vms
        return self.get_primary_vms()

    def modcmd_init(self, cmd_name: VmCmd):
        """Run init script for command.
        """
        cmd_cf = self.cf.view_section("cmd.%s" % cmd_name)
        init_script = cmd_cf.get("init", "")
        if init_script:
            # let subprocess see current env
            subenv = os.environ.copy()
            subenv["VMTOOL_ENV_NAME"] = self.full_role
            run_successfully([init_script], cwd=self.git_dir, shell=True, env=subenv)

        self.modcmd_prepare(cmd_name)

    def modcmd_prepare(self, cmd_name: VmCmd):
        """Prepare data package for command.
        """
        cmd_cf = self.cf.view_section("cmd.%s" % cmd_name)
        stamp_dirs = cmd_cf.getlist("stamp_dirs", [])
        cmd_abbr = cmd_cf.get("command_tag", "")
        globs = cmd_cf.getlist("files", [])
        use_admin = cmd_cf.getboolean("use_admin", False)

        self._PREP_TGZ_CACHE[cmd_name] = b""
        self.modcmd_build_tgz(cmd_name, globs, cmd_cf)

        self._PREP_STAMP_CACHE[cmd_name] = {
            "cmd_abbr": cmd_abbr,
            "stamp_dirs": stamp_dirs,
            "stamp": self.get_stamp(),
            "use_admin": use_admin,
        }

    def modcmd_run(self, cmd_name, vm_ids):
        """Send mod data to server and run it.
        """
        info = self._PREP_STAMP_CACHE[cmd_name]
        data_info = 0
        for vm_id in vm_ids:
            data = self._PREP_TGZ_CACHE[cmd_name]
            if not data_info:
                data_info = 1
            print("RUNNING...")
            self.run_mod_data(data, vm_id, use_admin=info["use_admin"], title=cmd_name)
            if info["cmd_abbr"]:
                self.set_stamp(vm_id, info["cmd_abbr"], info["stamp"], *info["stamp_dirs"])

    def process_pkgs(self):
        """Merge per-pkg variables into main config.

        Converts:

            [pkg.foo]
            pkg_pyinstall_vmlibs = a, b
            [pkg.bar]
            pkg_pyinstall_vmlibs = c, d

        To:
            [vm-config]
            pkg_pyinstall_vmlibs = a, b, c, d
        """
        cf = self.cf.cf
        vmap = {}
        for sect in cf.sections():
            if sect.startswith("pkg."):
                for opt in cf.options(sect):
                    if opt not in vmap:
                        vmap[opt] = []
                    done = set(vmap[opt])
                    val = cf.get(sect, opt)
                    for v in val.split(","):
                        v = v.strip()
                        if v and (v not in done):
                            vmap[opt].append(v)
                            done.add(v)
        for k, v in vmap.items():
            cf.set("vm-config", k, ", ".join(v))

    # in use
    def modcmd_build_tgz(self, cmd_name, globs, cmd_cf=None):
        cwd = self.git_dir
        os.chdir(cwd)

        defs = {}
        mods_ok = True
        vmlibs = []
        cert_fns = set()
        if cmd_cf:
            vmlibs = cmd_cf.getlist("vmlibs", [])
        if vmlibs:
            done_vmlibs = []
            vmdir = "vmlib"
            globs = list(globs)
            for mod in vmlibs:
                if mod in done_vmlibs:
                    continue
                if not mod:
                    continue
                mdir = os.path.join(vmdir, mod)
                if not os.path.isdir(mdir):
                    printf("Missing module: %s" % mdir)
                    mods_ok = False
                elif not os.path.isfile(mdir + "/setup.sh"):
                    printf("Broken module, no setup.sh: %s" % mdir)
                    mods_ok = False
                globs.append("vmlib/%s/**" % mod)
                done_vmlibs.append(mod)

                cert_ini = os.path.join(mdir, "certs.ini")
                if os.path.isfile(cert_ini):
                    cert_fns.add(cert_ini)
            defs["vm_modules"] = "\n".join(done_vmlibs) + "\n"
            globs.append("vmlib/runner.*")
            globs.append("vmlib/shared/**")
        if not mods_ok:
            sys.exit(1)

        dst = self.make_tar_filter(defs)

        for tmp in globs:
            subdir = "."
            if isinstance(tmp, str):
                flist = xglob(tmp)
            else:
                subdir = tmp[1]
                if subdir and subdir != ".":
                    os.chdir(subdir)
                else:
                    subdir = "."
                flist = xglob(tmp[0])
                if len(tmp) > 2:
                    exlist = tmp[2:]
                    flist2 = []
                    for fn in flist:
                        skip = False
                        for ex in exlist:
                            if fnmatch.fnmatch(fn, ex):
                                skip = True
                                break
                        if not skip:
                            flist2.append(fn)
                    flist = iter(flist2)
                if subdir:
                    os.chdir(cwd)

            for fn in flist:
                real_fn = os.path.join(subdir, fn)
                if os.path.isdir(real_fn):
                    #dst.add_dir(item.path, stat.S_IRWXU, item.mtime)
                    pass
                else:
                    with open(real_fn, "rb") as f:
                        st = os.fstat(f.fileno())
                        data = f.read()
                        dst.add_file_data(fn, data, st.st_mode & stat.S_IRWXU, st.st_mtime)

        # pass parameters to cert.ini files
        defs = {"env_name": self.env_name}
        if self.role_name:
            defs["role_name"] = self.role_name
        if self.cf.has_section("ca-config"):
            items = self.cf.view_section("ca-config").items()
            defs.update(items)

        # create keys & certs
        for cert_ini in cert_fns:
            printf("Processing certs: %s", cert_ini)
            mdir = os.path.dirname(cert_ini)
            keys = load_cert_config(cert_ini, self.load_ca_keypair, defs)
            for kname in keys:
                key, cert, _ = keys[kname]
                key_fn = "%s/%s.key" % (mdir, kname)
                cert_fn = "%s/%s.crt" % (mdir, kname)
                dst.add_file_data(key_fn, key, 0o600)
                dst.add_file_data(cert_fn, cert, 0o600)

        # finish
        dst.close()
        tgz = dst.getvalue()
        self._PREP_TGZ_CACHE[cmd_name] = tgz
        time_printf("%s: tgz bytes: %s", cmd_name, len(tgz))

    def load_ca_keypair(self, ca_name):
        intca_dir = self.cf.get(ca_name + "_dir", "")
        if not intca_dir:
            intca_dir = self.cf.get("intca_dir")
        pat = "%s/%s/%s_*.key.gpg" % (self.keys_dir, intca_dir, ca_name)
        res = list(sorted(xglob(pat)))
        if not res:
            raise UsageError("CA not found: %s - %s" % (ca_name, intca_dir))
        #names = [fn.split("/")[-1] for fn in res]
        idx = 0   # -1
        last_key = res[idx]
        #printf("CA: using %s from [%s]", names[idx], ", ".join(names))
        last_crt = last_key.replace(".key.gpg", ".crt")
        if not os.path.isfile(last_crt):
            raise UsageError("CA cert not found: %s" % last_crt)
        if not os.path.isfile(last_key):
            raise UsageError("CA key not found: %s" % last_key)
        return (last_key, last_crt)

    def run_mod_data(self, data, vm_id, use_admin=False, title=None):

        tmp_uuid = str(uuid.uuid4())
        run_user = "root"

        launcher = './tmp/%s/vmlib/runner.sh "%s"' % (tmp_uuid, vm_id)
        rm_cmd = "rm -rf"
        if run_user:
            launcher = "sudo -nH -u %s %s" % (run_user, launcher)
            rm_cmd = "sudo -nH " + rm_cmd

        time_printf("%s: Sending data - %d bytes", vm_id, len(data))
        decomp_script = 'install -d -m 711 tmp && mkdir -p "tmp/%s" && tar xzf - --warning=no-timestamp -C "tmp/%s"' % (
            tmp_uuid, tmp_uuid
        )
        self.vm_exec(vm_id, ["/bin/sh", "-c", decomp_script, "decomp"], data, use_admin=use_admin)

        time_printf("%s: Running", vm_id)
        cmdline = ["/bin/sh", "-c", launcher, "runit"]
        self.vm_exec_tmux(vm_id, cmdline, use_admin=use_admin, title=title)

    def get_stamp(self):
        commit_id = local_cmd(["git", "rev-parse", "HEAD"])
        commit_id = commit_id[:7]   # same length as git log --abbrev-commit
        return commit_id

    def put_known_host_from_tags(self, vm_id):
        pass

    def change_cwd_adv(self):
        # cd .. until there is .git
        if not self._change_cwd_gittop():
            os.chdir(self.git_dir)

    def _change_cwd_gittop(self):
        vmlib = "vmlib/runner.sh"
        num = 0
        maxstep = 30
        pfx = "."
        while True:
            if os.path.isdir(os.path.join(pfx, ".git")):
                if os.path.isfile(os.path.join(pfx, vmlib)):
                    os.chdir(pfx)
                    return True
                else:
                    break
            if num > maxstep:
                break
            pfx = os.path.join(pfx, "..")
            num += 1
        return False

    def run_console_cmd(self, cmd, cmdargs):
        cmd_cf = self.cf.view_section("cmd.%s" % cmd)
        cmdline = cmd_cf.get("vmrun")
        argparam = cmd_cf.get("vmrun_arg_param", "")

        fullcmd = shlex.split(cmdline)
        vm_ids, args = self.get_vm_args(cmdargs, allow_multi=True)
        if args:
            if argparam:
                fullcmd = fullcmd + [argparam, " ".join(args)]
            else:
                fullcmd = fullcmd + args

        if len(vm_ids) > 1 and self.options.tmux:
            raise UsageError("Cannot use tmux in parallel")

        for vm_id in vm_ids:
            if len(vm_ids) > 1:
                time_printf("Running on VM %s", vm_id)
            self.vm_exec_tmux(vm_id, fullcmd, title=cmd)

    def cmd_show_config(self, *args):
        """Show filled config for current VM.

        Group: config
        """
        desc = self.env_name
        if self.role_name:
            desc += "." + self.role_name

        fail = 0
        for sect in sorted(self.cf.sections()):
            sect_header = f"[{sect}]"
            for k in sorted(self.cf.cf.options(sect)):
                if args and k not in args:
                    continue
                if sect_header:
                    printf(sect_header)
                    sect_header = ""
                try:
                    raw = self.cf.cf.get(sect, k, raw=True)
                    v = self.cf.cf.get(sect, k)
                    vs = v
                    if not self.options.verbose:
                        vs = vs.strip()
                        if vs.startswith("----") or vs.startswith("{"):
                            vs = vs.split("\n")[0]
                        else:
                            vs = re.sub(r"\n\s*", " ", vs)
                        printf("%s = %s", k, vs)
                    else:
                        printf("%s = %s [%s] (%s)", k, vs, desc, raw)
                except Exception as ex:
                    fail = 1
                    eprintf("### ERROR ### key: '%s.%s' err: %s", sect, k, str(ex))
            if not sect_header:
                printf("")
        if fail:
            sys.exit(fail)

    def cmd_show_config_raw(self, *args):
        """Show filled config for current VM.

        Group: config
        """
        self.cf.cf.write(sys.stdout)

    def cmd_check_config(self):
        """Check if config works.

        Group: config
        """
        fail = 0
        for k in self.cf.options():
            try:
                self.cf.getlist(k)
            except Exception as ex:
                fail = 1
                printf("key: '%s' err: %s", k, str(ex))
        if fail:
            printf("--problems--")
            sys.exit(fail)

    def work(self):
        cmd = self.options.command
        cmdargs = self.options.args
        if not cmd:
            raise UsageError("Need command")
        #eprintf("vmtool - env_name: %s  git_dir: %s", self.env_name, self.git_dir)
        cmd_section = "cmd.%s" % cmd
        if self.cf.has_section(cmd_section):
            cf2 = self.cf.view_section(cmd_section)
            if cf2.get("vmlibs", ""):
                vms = self.load_modcmd_args(cmdargs)
                self.change_cwd_adv()
                self.modcmd_init(cmd)
                self.modcmd_run(cmd, vms)
            else:
                self.run_console_cmd(cmd, cmdargs)
        else:
            super().work()

    def set_stamp(self, vm_id, name, commit_id, *dirs):
        raise NotImplementedError

    def vm_lookup(self, vm_id, ignore_env=False, cache=True):
        raise NotImplementedError

    def get_primary_vms(self):
        raise NotImplementedError

    def get_vm_args(self, args, allow_multi=False):
        """Check if args start with VM ID.

        returns: (vm-id, args)
        """
        raise NotImplementedError

