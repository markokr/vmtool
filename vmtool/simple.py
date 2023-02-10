"""Simple backend for vmtool.
"""

import shlex
import sys

from vmtool.base import VmToolBase
from vmtool.scripting import UsageError
from vmtool.util import eprintf, time_printf


class VmTool(VmToolBase):
    __doc__ = __doc__

    _vm_map = None

    def conf_func_tf(self, arg, sect, kname):
        return ""

    def conf_func_primary_vm(self, arg, sect, kname):
        """Lookup primary vm.

        Usage: ${PRIMARY_VM ! ${other_role}}
        """
        vm = self.get_primary_for_role(arg)
        return vm["InstanceId"]

    def vm_lookup(self, vm_id, ignore_env=False, cache=True):
        if self._vm_map is None:
            self._vm_map = {}
        if vm_id in self._vm_map and cache:
            return self._vm_map[vm_id]

        #res = self.cf.cf.get("primary-vms", vm_id)
        vm = {"id": vm_id, "PublicIpAddress": vm_id, "PrivateIpAddress": vm_id, "NetworkInterfaces": []}
        self._vm_map[vm_id] = vm
        return vm

    def get_env_filters(self):
        """Return default filters based on command-line swithces.
        """
        return self.make_env_filters(role_name=self.role_name, running=self.options.running, allenvs=self.options.all)

    def make_env_filters(self, role_name=None, running=True, allenvs=False):
        """Return filters for instance listing.
        """
        filters = []

        if not allenvs:
            filters.append({"Name": "tag:Env", "Values": [self.env_name]})
            if role_name or self.role_name:
                filters.append({"Name": "tag:Role", "Values": [role_name or self.role_name]})

        if running:
            filters.append({"Name": "instance-state-name", "Values": ["running"]})

        return filters

    def get_primary_for_role(self, role_name, instance_id=None):
        vm_id = self.cf.cf.get("primary-vms", role_name)
        if vm_id:
            return self.vm_lookup(vm_id)
        raise UsageError("Primary VM not found: %s" % role_name)

    def get_primary_vms(self):
        if self.options.all_role_vms:
            return self.get_all_role_vms()
        if self.options.all_role_fo_vms or self.options.earlier_fo_vms or self.options.latest_fo_vm:
            return self.get_all_role_fo_vms()

        main_vms = self._get_primary_vms()
        if main_vms:
            eprintf("Primary VM for %s is %s", self.full_role, ",".join(main_vms))
            return main_vms
        raise UsageError("Primary VM not found")

    def _get_primary_vms(self):
        #return [self.role_name]
        vm_id = self.cf.cf.get("primary-vms", self.role_name)
        if vm_id:
            return [vm_id]
        return []

    def get_all_role_vms(self):
        if not self.role_name:
            raise UsageError("Not in a role-based env")

        all_vms = self._get_primary_vms()
        if not all_vms:
            eprintf("No running VMs for %s", self.full_role)
        else:
            eprintf("Running VMs for %s: %s", self.full_role, " ".join(all_vms))
        return all_vms

    def get_all_role_fo_vms(self):
        if not self.role_name:
            raise UsageError("Not in a role-based env")

        eprintf("No running failover VMs for %s", self.full_role)
        return []

    def _check_tags(self, taglist, force_role=False, role_name=None):
        if role_name is None:
            role_name = self.role_name
        if not taglist:
            return False

        gotenv = gotrole = False
        for tag in taglist:
            if tag["Key"] == "Env":
                gotenv = True
                if tag["Value"] != self.env_name:
                    return False
            if tag["Key"] == "Role":
                gotrole = True
                if role_name and tag["Value"] != role_name:
                    return False
        if not gotenv:
            return False
        if not gotrole and role_name:
            return False
        elif force_role and not role_name:
            return False
        return True

    def get_vm_args(self, args, allow_multi=False):
        """Check if args start with VM ID.

        returns: (vm-id, args)
        """
        if args and args[0][:2] == "i-":
            vm_list = [args[0]]
            args = args[1:]
        else:
            vm_list = self.get_primary_vms()

        if allow_multi:
            return vm_list, args

        if len(vm_list) != 1:
            raise UsageError("Command does not support multiple vms")
        return vm_list[0], args

    def ssh_cmdline(self, vm_id, use_admin=False, check_tty=False):
        if check_tty and sys.stdout.isatty():        # pylint:disable=no-member
            cmd = self.cf.get("ssh_tty_cmd")
        else:
            cmd = self.cf.get("ssh_connect_cmd")
        return shlex.split(cmd)

    def cmd_ssh(self, *args):
        """SSH to VM and run command (optional).

        Group: admin
        """
        vm_ids, args = self.get_vm_args(args, allow_multi=True)
        for vm_id in vm_ids:
            if len(vm_ids) > 1:
                time_printf("Running on VM %s", vm_id)
            if len(args) == 1:
                self.vm_exec_tmux(vm_id, args[0], title="ssh")
            else:
                self.vm_exec_tmux(vm_id, args or ["bash", "-l"], title="ssh")

    def cmd_ssh_admin(self, *args):
        """SSH to VM and run command (optional).

        Group: admin
        """
        vm_ids, args = self.get_vm_args(args, allow_multi=True)
        for vm_id in vm_ids:
            if len(vm_ids) > 1:
                time_printf("Running on VM %s", vm_id)
            if len(args) == 1:
                self.vm_exec_tmux(vm_id, args[0], use_admin=True, title="ssh-admin")
            else:
                self.vm_exec_tmux(vm_id, args or [], use_admin=True, title="ssh-admin")

    def cmd_rsync(self, *args):
        """Use rsync to transport files.

        Group: admin
        """
        if len(args) < 2:
            raise UsageError("Need source and dest for rsync")
        self.vm_rsync(*args)

    def cmd_tmux_attach(self, vm_id):
        """Attach to regular non-admin session.

        Group: vm
        """
        cmdline = shlex.split(self.cf.get("tmux_attach"))
        self.vm_exec(vm_id, cmdline, None, use_admin=False)

    def cmd_tmux_attach_admin(self, vm_id):
        """Attach to admin session.

        Group: vm
        """
        cmdline = shlex.split(self.cf.get("tmux_attach"))
        self.vm_exec(vm_id, cmdline, None, use_admin=True)

    def cmd_show_primary(self):
        """Show primary VM id.

        Group: internal
        """
        ids = self.get_primary_vms()
        print(ids[0])

    def load_modcmd_args(self, args):
        vms = []
        for a in args:
            if a.startswith("i-"):
                vms.append(a)
            else:
                raise UsageError("command supports only vmid args")
        if vms:
            return vms
        return self.get_primary_vms()

    def set_stamp(self, vm_id, name, commit_id, *dirs):
        return

