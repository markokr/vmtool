Usage
=====

It loads setup from environment-specific config file::

    $ vmtool [--env=ENV] COMMAND ...

Where:

* Cloud config is specified by ``--env=ENV`` command-line switch or ``VMTOOL_ENV_NAME``
  environment variable.

* Other environment variables:
  
  - ``VMTOOL_CONFIG_DIR`` (default: $gittop/vmconf) 
  - ``VMTOOL_KEY_DIR`` (default: $gittop/keys) 
  - ``VMTOOL_ENV_NAME`` (no default)

* Final config file is: ``${VMTOOL_CONFIG_DIR}/config_${env}.ini``

Commands are defined in config file.  A command can launch shell scripts in VM
or run AWS API calls.
