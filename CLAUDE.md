# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

vmtool is an orchestration tool for managing stateful cloud VMs on AWS. It's designed for database and other stateful workloads, providing comprehensive VM lifecycle management, backup handling, failover capabilities, and cost tracking.

## Development Commands

### Testing
```bash
# Run all tests with coverage
tox

# Run tests with pytest directly (after installing deps)
pytest --cov

# Run linting
tox -e lint
# or
pylint vmtool
```

### Running vmtool

The tool can be run in two ways:

1. **Via wrapper script** (auto-manages virtualenv):
```bash
./run_vmtool.sh --env=ENV_NAME COMMAND [args...]
```

2. **Direct invocation** (after pip install):
```bash
vmtool --env=ENV_NAME COMMAND [args...]
```

### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## Architecture

### Command Execution Flow

1. **Entry**: `vmtool/run.py` - Parses CLI args, loads environment config
2. **Config Loading**: `vmtool/envconfig.py` - Loads `config_${env}.ini` from conf directory
3. **Command Dispatch**: `vmtool/scripting.py` - EnvScript base class dispatches to `cmd_*` methods
4. **Implementation**: `vmtool/aws.py` - VmTool class with 70+ command implementations

### Key Components

- **vmtool/aws.py**: Main VmTool class inheriting from EnvScript. Contains all VM management commands as `cmd_*` methods (e.g., `cmd_create`, `cmd_start`, `cmd_ssh`)
- **vmtool/config.py**: Advanced config parser with variable interpolation, supports `${var}` syntax and custom functions like `${FILE!path}`, `${TF!var}`
- **vmtool/envconfig.py**: Environment-specific config loading. Looks for configs in `$git_dir/conf/config_${env}.ini`
- **vmtool/scripting.py**: EnvScript base class providing command dispatch, logging, and config management
- **vmtool/terra.py**: Terraform state file parsing for reading output variables
- **vmtool/certs.py**: Certificate management integration with sysca
- **vmtool/gpg.py**: GPG file decryption utilities
- **vmtool/util.py**: Common utilities (SSH, formatting, subprocess helpers)

### Configuration System

vmtool uses a sophisticated INI-based config system:

- **Location**: `${VMTOOL_CONFIG_DIR}/config_${env}.ini` (default: `$gittop/conf/`)
- **Main section**: `[vm-config]`
- **Interpolation**: Supports recursive variable expansion with `${var}` and `${section:var}`
- **Functions**: Custom interpolation functions via `${FUNC!arg}` syntax:
  - `FILE`: Read file contents
  - `KEY`: Read SSH key
  - `TF`: Read Terraform output variable
  - `TFAZ`: Read Terraform AZ variable
  - `PRIMARY_VM`: Get primary VM identifier
- **Dependencies**: Can include other configs via `config_depends = file1.ini, file2.ini`
- **Aliases**: Support command and role aliases via `[alias.command_name]` sections

### Environment Variables

- `VMTOOL_ENV_NAME`: Environment name (can be overridden with `--env`)
- `VMTOOL_CONFIG_DIR`: Config directory (default: `$gittop/vmconf` or `$gittop/conf`)
- `VMTOOL_KEY_DIR`: SSH keys directory (default: `$gittop/keys`)
- `VMTOOL_CA_LOG_DIR`: CA log directory (required)
- `VMTOOL_GIT_DIR`: Git repository root (auto-detected or can be set)
- `VMTOOL_USERNAME`: Username for VM access (fallback to `USER` or `LOGNAME`)

### Command Pattern

New commands are added as methods in `vmtool/aws.py`:
```python
def cmd_commandname(self, *args):
    """Command description."""
    # Implementation
```

The method name determines the command: `cmd_show_vms` → `vmtool show-vms` (dashes converted to underscores).

## Project Structure

```
vmtool/
├── vmtool/          # Main package
│   ├── run.py       # CLI entry point and command routing
│   ├── aws.py       # VmTool class with all commands (~4500 lines)
│   ├── config.py    # Advanced config parser
│   ├── envconfig.py # Environment config loader
│   ├── scripting.py # EnvScript base class
│   ├── terra.py     # Terraform integration
│   ├── certs.py     # Certificate management
│   ├── gpg.py       # GPG utilities
│   ├── util.py      # Common utilities
│   └── xglob.py     # Extended glob matching
├── tests/           # Unit tests
├── pricing/         # AWS pricing analysis scripts
├── requirements.txt # Python dependencies
├── setup.py         # Package setup
├── tox.ini          # Test configuration
└── run_vmtool.sh    # Wrapper script with auto-venv
```

## Pricing Scripts

The `pricing/` directory contains AWS pricing analysis tools:
```bash
# Fetch pricing data
cd pricing
./fetch_cache.py

# Query instance prices
./list_vms.py --region='eu-west-*' m5.large
```

## Key Operations

### VM Lifecycle
- Create: `create`, `create_primary`, `create_secondary`
- Control: `start`, `stop`, `terminate`
- Access: `ssh`, `ssh_admin`, `rsync`
- Info: `show_vms`, `show_primary`, `get_output`

### High Availability
- `failover`: Promote secondary to primary
- `takeover`: Coordinated primary/secondary switch
- `drop_node`: Remove node from cluster

### Backup Management
- `show_backups`, `ls_backups`: List backups
- `get_backup`: Restore from backup
- `clean_backups`: Remove old backups

### Cost Tracking
- `show_vmcost`: VM costs
- `show_ebscost`: EBS volume costs
- `show_s3cost`: S3 bucket costs

## Testing Notes

- Unit tests in `tests/` cover config parsing and utility functions
- Test individual modules with: `pytest tests/test_module.py`
- The main aws.py module has extensive manual testing requirements due to AWS API dependencies
- Use `--cov` flag for coverage reports

## Code Style

- Python 3 codebase
- Uses pylint for linting (config in `.pylintrc`)
- Line length and other style rules defined in pylintrc
- Prefer explicit over implicit, especially for AWS operations
