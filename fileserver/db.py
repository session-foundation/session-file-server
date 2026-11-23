from . import config
from .postfork import postfork
from .web import app

from flask import g
from psycopg_pool import ConnectionPool
from werkzeug.local import LocalProxy
import atexit


psql_pool = None


@postfork
def pg_connect():
    global psql_pool

    # Test suite sets this to handle the connection itself:
    if 'defer' in config.pgsql_connect_opts:
        return

    conninfo = config.pgsql_connect_opts.pop('conninfo', '')
    # No psql_pool.wait() here: if the pool can't fill within its timeout, wait() *closes* the pool
    # permanently.  That happens when a worker spawns while postgresql is down or still starting
    # (e.g. at boot), and since uwsgi swallows postfork exceptions the worker keeps running with a
    # dead pool and fails every request with PoolClosed.  Without it, the pool keeps retrying in the
    # background and starts serving requests once the database is reachable.
    psql_pool = ConnectionPool(
        conninfo, open=True, min_size=2, max_size=32, kwargs={**config.pgsql_connect_opts, "autocommit": True}
    )


@atexit.register
def close_db_pool():
    global psql_pool
    if psql_pool is not None:
        psql_pool.close()


def get_psql_conn():
    global psql_pool
    if "psql" not in g:
        g.psql = psql_pool.getconn()

    return g.psql


@app.teardown_appcontext
def release_psql_conn(exception):
    psql = g.pop("psql", None)

    if psql is not None:
        psql_pool.putconn(psql)


psql = LocalProxy(get_psql_conn)
