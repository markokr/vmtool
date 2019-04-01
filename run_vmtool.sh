#! /bin/sh

# run vmtool in automatically generated virtualenv

CURVER=1
PYTHON=python3

top=$(dirname $(realpath $0))
venv="$HOME/.vmtool-venv"
ver="$venv/ver.txt"

set -e

refresh=1
if test -f "$ver"; then
  OLDVER=`cat $ver`
  if test "$CURVER" = "$OLDVER"; then
    refresh=0
  fi
fi

if test "$refresh" = "1"; then
  rm -rf "$venv"
  $PYTHON -m virtualenv -p "$PYTHON" "$venv"
  "$venv"/bin/pip install -r "$top/requirements.txt"
  echo "$CURVER" > "$ver"
fi

PYTHONPATH="${top}:${PYTHONPATH}" \
exec "$venv"/bin/python -m vmtool.run "$@"

