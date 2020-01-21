#!/bin/bash
set -euo pipefail

CN="cn=admin,dc=flipdot,dc=org"
HOST=ldap.flipdot.space

PW="${PW:-}"

ARGS=(
    -D "$CN"
    -h "$HOST"
)

function usage() {
            cat <<EOF
Usage:
    ./ldap.sh command [args]

Commands

    search      alias for ldapsearch

    add         alias for add

Environment

    PW          preset connect pw

EOF
        exit 1
}

if [[ "$PW" == "" ]]; then
    ARGS+=(-W)
else
    ARGS+=(-w "$PW")
fi


if [[ "$*" == "" ]]; then
    usage
fi
arg=$1
shift

function search() {
    ldapsearch "${ARGS[@]}" "$@"
}

case "$arg" in
    search)
        search "$@"
    ;;
    ls)
        search -b 'dc=flipdot,dc=org' "$@"
    ;;
    add)
        ldapadd "${ARGS[@]}" "$@"
    ;;
    *)
        usage
    ;;
esac
