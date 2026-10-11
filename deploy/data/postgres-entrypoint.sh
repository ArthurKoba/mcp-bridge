#!/bin/sh
# Bootstrap four independent databases in the EXISTING Data PostgreSQL service.
# The upstream entrypoint remains responsible for pg_initdb and normal PGDATA.
set -eu
if [ "${1:-postgres}" != "postgres" ]; then
    exec /usr/local/bin/docker-entrypoint.sh "$@"
fi
: "${POSTGRES_USER:?}"
: "${POSTGRES_PASSWORD:?}"
ready_file=/run/briareus-owner-databases-ready
rm -f "$ready_file"
child=
stop_server() {
    if [ -n "$child" ]; then
        kill -TERM "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
}
trap 'stop_server' INT TERM HUP
/usr/local/bin/docker-entrypoint.sh "$@" &
child=$!
i=0
while [ "$i" -lt 90 ]; do
    if ! kill -0 "$child" 2>/dev/null; then
        wait "$child" || exit $?
        echo 'briareus owner bootstrap: postgres exited before readiness' >&2
        exit 1
    fi
    if pg_isready -h 127.0.0.1 -p 5432 -U "$POSTGRES_USER" -d postgres >/dev/null 2>&1; then
        # This credential stays in process environment; never pass it through
        # argv or echo it. The owner credentials below are consumed exclusively
        # by psql's \getenv and safely quoted with :'variable'.
        export PGPASSWORD="$POSTGRES_PASSWORD"
        if ! psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -p 5432 \
            -U "$POSTGRES_USER" -d postgres \
            -f /usr/local/share/briareus/owner-bootstrap.psql >/dev/null; then
            echo 'briareus owner bootstrap: failed; PostgreSQL health remains blocked' >&2
            stop_server
            exit 1
        fi
        unset PGPASSWORD
        touch "$ready_file"
        echo 'briareus owner bootstrap: four databases and restricted roles verified'
        wait "$child"
        exit $?
    fi
    i=$((i + 1))
    sleep 1
done
echo 'briareus owner bootstrap: PostgreSQL readiness timeout' >&2
stop_server
exit 1
