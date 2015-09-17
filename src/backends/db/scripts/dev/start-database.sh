#! /bin/bash

# Copyright 2008-2015 Canonical
# Copyright 2015 Chicharreros (https://launchpad.net/~chicharreros)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# For further info, check  http://launchpad.net/magicicada-server

ROOTDIR=${ROOTDIR:-`bzr root`}
if [ ! -d "$ROOTDIR"  ]; then
    echo "ROOTDIR '$ROOTDIR' doesn't exist" >&2
    exit 1
fi

DATABASES="
filesync
graphite
"

function setup_database() {
    local TESTDIR=$1

    echo "## Starting postgres in $TESTDIR ##"
    mkdir -p "$TESTDIR/data"
    chmod 700 "$TESTDIR/data"

    export PGHOST="$TESTDIR"
    export PGDATA="$TESTDIR/data"
    if [ -d /usr/lib/postgresql/9.1 ]; then
        export PGBINDIR=/usr/lib/postgresql/9.1/bin
    else
        echo "Cannot find valid parent for PGBINDIR"
    fi
    $PGBINDIR/initdb -E UNICODE -D $PGDATA
    # set up the database options file
    if [ ! -e $PGDATA/postgresql.conf ]; then
        echo "PostgreSQL data directory apparently didn't init"
    else
    (
        cat <<EOF
search_path='\$user,public,ts2'
log_statement='all'
log_line_prefix='[%m] %q%u@%d %c '
fsync = off
EOF
    ) > $PGDATA/postgresql.conf
    fi
    $PGBINDIR/initdb -A trust &>/dev/null
    $PGBINDIR/pg_ctl start -w -D $TESTDIR/data -l $TESTDIR/postgres.log -o "-F -k $TESTDIR -h ''"
    for db in $DATABASES; do
        $PGBINDIR/createdb --encoding UNICODE "$db" &>/dev/null
        $PGBINDIR/createlang plpgsql "$db"
    done
    $PGBINDIR/createuser --superuser --createdb "postgres" &>/dev/null
    echo "To set your environment so psql will connect to this DB instance type:"
    echo "    export PGHOST=$TESTDIR"
    echo "## Done (start-database.sh). ##"
}

setup_database /dev/shm/pg_magicicada
