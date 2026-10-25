#!/bin/sh
# Creates an isolated, small reference environment; never installs torch/weights.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"
python=${PYTHON:-python3}
"$python" -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
venv="$repo/.venv-mentor"
if [ ! -x "$venv/bin/python" ]; then "$python" -m venv "$venv"; fi
if ! "$venv/bin/python" -c 'import dpkt,h11; assert dpkt.__version__=="1.9.8" and h11.__version__=="0.16.0"' 2>/dev/null; then
  "$venv/bin/python" -m pip install --disable-pip-version-check dpkt==1.9.8 h11==0.16.0
fi
exec "$venv/bin/python" scripts/validation/run_mentor_demo.py "$@"
