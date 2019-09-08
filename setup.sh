#!/bin/bash
set -euxo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ENV=.env
PIP=$ENV/bin/pip

make_venv() {
    [[ -x $PIP ]] || python2 -m virtualenv $ENV
    $PIP install -r requirements.txt
}

make_venv
