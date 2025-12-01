from . import config
from .web import app
from . import db, http, utils, files

import flask
from flask import request, abort, Response
import secrets
from base64 import urlsafe_b64encode
from hashlib import blake2b
import json
from decimal import Decimal
from datetime import datetime, timezone
import psycopg
import time
import nacl
from nacl.signing import VerifyKey
import nacl.exceptions
import nacl.bindings as sodium

if config.BACKWARDS_COMPAT_IDS:
    assert all(x in (0, 1) for x in config.BACKWARDS_COMPAT_IDS_FIXED_BITS)
    BACKWARDS_COMPAT_MSB = sum(
        y << x for x, y in enumerate(reversed(config.BACKWARDS_COMPAT_IDS_FIXED_BITS))
    )
    BACKWARDS_COMPAT_RANDOM_BITS = 53 - len(config.BACKWARDS_COMPAT_IDS_FIXED_BITS)


class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.timestamp()
        return super(CustomEncoder, self).default(obj)


def json_resp(data, status=200):
    """Takes data and optionally an HTTP status, returns it as a json response."""
    return flask.Response(
        json.dumps(data, cls=CustomEncoder), status=status, mimetype="application/json"
    )


def error_resp(code):
    """
    Simple JSON error response to send back, embedded as `status_code` and also as the HTTP response
    code.
    """
    return json_resp({"status_code": code}, code)


def generate_file_id(data):
    """
    Generate a file ID by blake2b hashing the file body, then using a 33-byte digest encoded into 44
    base64url chars.  (Ideally would be 32, but that would result in base64 padding, so increased to 33
    to fit perfectly).
    """
    return urlsafe_b64encode(
        blake2b(data, digest_size=33, salt=b"SessionFileSvr\0\0").digest()
    ).decode()


def abort_with_reason(code, msg, warn=True):
    if warn:
        app.logger.warning(msg)
    else:
        app.logger.debug(msg)
    abort(Response(msg, status=code, mimetype='text/plain'))


def valid_blinded_version_id_for_auth(request, required):
    """
    Check if a request is correctly authenticated, if the auth headers are missing and auth isn't
    required then just return 'None'.
    """
    pk, ts_str, sig_in = (
        request.headers.get(f"X-FS-{h}") for h in ('Pubkey', 'Timestamp', 'Signature')
    )
    missing = sum(x is None or x == '' for x in (pk, ts_str, sig_in))

    # If we were missing one of the auth headers and don't require auth then just return a 'None'
    if missing:
        if required or missing < 3:
            abort_with_reason(
                http.BAD_REQUEST,
                "Invalid authentication: one or more X-FS-* auth headers is missing",
            )
        else:
            return None

    # Parameter input validation

    try:
        blinded_version_id = pk
        pk = utils.decode_hex_or_b64(pk, 33)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: X-FS-Pubkey is not a valid 66-hex digit id"
        )

    if pk[0] != 0x07:
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: X-FS-Pubkey must be 07- prefixed"
        )
    pk = pk[1:]

    if not sodium.crypto_core_ed25519_is_valid_point(pk):
        abort_with_reason(
            http.BAD_REQUEST,
            "Invalid authentication: given X-FS-Pubkey is not a valid Ed25519 pubkey",
        )

    try:
        sig_in = utils.decode_hex_or_b64(sig_in, 64)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: X-FS-Signature is not base64[86]"
        )

    try:
        ts = int(ts_str)
    except Exception:
        abort_with_reason(
            http.BAD_REQUEST, "Invalid authentication: X-FS-Timestamp is not a valid timestamp"
        )

    # Parameter value validation

    now = time.time()
    if not now - 24 * 60 * 60 <= ts <= now + 24 * 60 * 60:
        abort_with_reason(
            http.TOO_EARLY, "Invalid authentication: X-FS-Timestamp is too far from current time"
        )

    # Signature validation

    # Signature should be on:
    #     TIMESTAMP || METHOD || PATH
    to_verify = str(ts).encode() + request.method.encode() + request.path.encode()

    # Work around flask deficiency: we can't use request.full_path above because it *adds* a `?`
    # even if there wasn't one in the original request.  So work around it by only appending if
    # there is a query string and, officially, don't accept `?` followed by an empty query string in
    # the auth request data (if you have no query string then don't append the ?).
    if len(request.query_string):
        to_verify = to_verify + b'?' + request.query_string

    if len(request.data):
        to_verify = to_verify + blake2b(request.data, digest_size=64)

    try:
        pk = VerifyKey(pk)
        pk.verify(to_verify, sig_in)
    except nacl.exceptions.BadSignatureError:
        abort_with_reason(
            http.UNAUTHORIZED, "Invalid authentication: X-FS-Signature verification failed"
        )

    return blinded_version_id


last_pool_fetch = 0
active_pools = []
last_pool_index = 0


def choose_pool() -> tuple[int, str]:
    global last_pool_fetch, active_pools, last_pool_index

    now = time.time()
    if not active_pools or now - last_pool_fetch > 10:
        active_pools = []
        last_pool_fetch = now
        with db.psql.cursor() as cur:
            cur.execute("SELECT id, name FROM storage_pools WHERE active ORDER BY id")
            for id, name in cur:
                active_pools.append((id, name))
        if not active_pools:
            raise RuntimeError("Error: no storage pools are active!")

    last_pool_index = (last_pool_index + 1) % len(active_pools)
    return active_pools[last_pool_index]


@app.post("/file")
def submit_file(*, body=None, deprecated=False):
    if body is None:
        body = request.data

    if not 0 < len(body) <= config.MAX_FILE_SIZE:
        app.logger.warning(
            "Rejecting upload of size {} ∉ (0, {}]".format(len(body), config.MAX_FILE_SIZE)
        )
        return error_resp(http.PAYLOAD_TOO_LARGE)

    ttl = config.FILE_EXPIRY
    requested_ttl = request.headers.get('X-FS-TTL') if config.MAX_FILE_TTL is not None else None
    if requested_ttl is not None:
        try:
            requested_ttl = int(requested_ttl)
        except ValueError:
            return error_resp(http.BAD_REQUEST)
        if requested_ttl < 0 or requested_ttl > config.MAX_FILE_TTL:
            return error_resp(http.BAD_REQUEST)
        ttl = f"{requested_ttl} seconds"

    id = None
    expiry = None
    try:
        pool_id, pool_name = choose_pool()

        new_file = True
        if config.BACKWARDS_COMPAT_IDS:
            done = False
            for attempt in range(25):

                id = BACKWARDS_COMPAT_MSB << BACKWARDS_COMPAT_RANDOM_BITS | secrets.randbits(
                    BACKWARDS_COMPAT_RANDOM_BITS
                )
                id_str = str(id)
                if not deprecated:
                    id = id_str  # New ids are always strings; legacy requests require we return an integer
                try:
                    with db.psql.cursor() as cur:
                        cur.execute(
                            "INSERT INTO files (id, expiry, pool) VALUES (%s, NOW() + %s, %s) RETURNING expiry",
                            (id_str, ttl, pool_id),
                        )
                        expiry = cur.fetchone()[0]
                except psycopg.errors.UniqueViolation:
                    continue

                done = True
                break

            if not done:
                app.logger.error(
                    "Tried 25 random IDs and got all constraint failures, something getting wrong!"
                )
                return error_resp(http.INSUFFICIENT_STORAGE)

        else:
            id = generate_file_id(body)
            with db.psql.transaction(), db.psql.cursor() as cur:
                cur.execute(
                    """
                        WITH inserted_file AS (
                            INSERT INTO files (id, expiry, pool) VALUES (%s, NOW() + %s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                                uploaded = NOW(),
                                expiry = GREATEST(EXCLUDED.expiry, files.expiry)
                            RETURNING expiry, pool, (xmax = 0) AS inserted
                        )
                        SELECT
                            i_f.expiry,
                            i_f.inserted,
                            CASE WHEN NOT i_f.inserted THEN
                                (SELECT name FROM storage_pools WHERE id = i_f.pool)
                            ELSE
                                NULL
                            END AS new_pool
                        FROM inserted_file i_f
                        """,
                    (id, ttl, pool_id),
                )
                expiry, new_file, updated_pool_name = cur.fetchone()

                if updated_pool_name is not None:
                    # If this comes back non-null then we updated rather than inserted, and
                    # so our pool name might have changed:
                    pool_name = updated_pool_name

        if new_file:
            files.store(pool_name, id, body)

    except Exception as e:
        app.logger.error("Failed to insert/store file: {}".format(e))
        return error_resp(http.INTERNAL_SERVER_ERROR)

    response = (
        {"result": id, "status_code": 200}
        if deprecated
        else {"id": id, "expires": expiry.timestamp()}
    )
    return json_resp(response)


@app.post("/files")
def submit_file_old():
    input = request.json
    if input is None or "file" not in input:
        app.logger.warning("Invalid request: did not find json with a 'file' property")
        return error_resp(http.BAD_REQUEST)

    body = input["file"]
    if not 0 < len(body) <= config.MAX_FILE_SIZE_B64:
        app.logger.warning(
            "Rejecting upload of b64-encoded size {} ∉ (0, {}]".format(
                len(body), config.MAX_FILE_SIZE_B64
            )
        )
        return error_resp(http.PAYLOAD_TOO_LARGE)

    body = utils.decode_base64(body)

    return submit_file(body=body, deprecated=True)


@app.get("/file/<id>")
def get_file(id):
    with db.psql.cursor() as cur:
        cur.execute("SELECT expiry, pool_name FROM pool_files WHERE id = %s", (id,), binary=True)
        row = cur.fetchone()

        now = datetime.now(timezone.utc)
        if not row or row[0] <= now:
            app.logger.debug("File '{}' does not exist".format(id))
            return error_resp(http.NOT_FOUND)

        expiry, pool_name = row

        path = files.get_file_path(pool_name, id)
        response = flask.make_response(path.read_bytes())

        response.expires = expiry

        # TODO/FIXME:
        response.headers.set("Content-Type", "application/octet-stream")
        return response
        # because the following won't work through onion requests currently because of the internal
        # subrequest that we do for onion requests: it gives the error:
        #   Attempted implicit sequence conversion but the response object is in direct passthrough mode.
        # FIXME: perhaps we could detect whether we are a subrequest, and if so, do it this way but
        # otherwise send it as-is (i.e. for future Lokinet direct access)?
        return flask.send_file(
            files.get_file_path(pool_name, id),
            mimetype="application/octet-stream",
            as_attachment=True,
            etag=False,
            conditional=False,
            max_age=(row[0] - now).total_seconds(),
        )


@app.get("/files/<id>")
def get_file_old(id):
    with db.psql.cursor() as cur:
        cur.execute("SELECT expiry, pool_name FROM pool_files WHERE id = %s", (id,), binary=True)
        row = cur.fetchone()

        if not row or row[0] <= datetime.now(timezone.utc):
            app.logger.debug("File '{}' does not exist".format(id))
            return error_resp(http.NOT_FOUND)

        path = files.get_file_path(row[1], id)
        return json_resp({"status_code": 200, "result": utils.encode_base64(path.read_bytes())})


@app.get("/file/<id>/info")
def get_file_info(id):
    with db.psql.cursor() as cur:
        cur.execute("SELECT uploaded, expiry, pool_name FROM pool_files WHERE id = %s", (id,))
        row = cur.fetchone()

        if row and row[1] <= datetime.now(timezone.utc):
            row = None

        size = None
        if row:
            try:
                size = files.get_file_path(row[2], id).stat().st_size
            except FileNotFoundError:
                app.logger.warning(f"File {id} in database not found on disk!")
                row = None

        if not row:
            app.logger.debug("File '{}' does not exist".format(id))
            return error_resp(http.NOT_FOUND)

        return json_resp(
            {"size": size, "uploaded": row[0].timestamp(), "expires": row[1].timestamp()}
        )


@app.post("/file/<id>/extend")
def extend_file_expiry(id):
    """
    Extend an existing file's expiry.  We accept the same X-FS-TTL header as the original upload to
    extend by a specific value, otherwise extend by the default storage interval.

    This endpoint will only extend but not reduce a file expiry (so that someone cannot prematurely
    expire someone else's file once they know the id).
    """
    ttl = config.FILE_EXPIRY
    requested_ttl = request.headers.get('X-FS-TTL') if config.MAX_FILE_TTL is not None else None
    if requested_ttl is not None:
        try:
            requested_ttl = int(requested_ttl)
        except ValueError:
            return error_resp(http.BAD_REQUEST)
        if requested_ttl < 0 or requested_ttl > config.MAX_FILE_TTL:
            return error_resp(http.BAD_REQUEST)
        ttl = f"{requested_ttl} seconds"

    # Don't allow an extension of a backwards-compat ID because there is too much of a risk of
    # collisions where it might seem like you updated, but actually it expired and someone else
    # uploaded a file that happened to get the same ID.
    if len(id) < 44:
        app.logger.warning("Denying attempt to extend a backwards compat ID")
        return error_resp(http.NOT_FOUND)

    with db.psql.cursor() as cur:
        cur.execute(
            """
            UPDATE files SET expiry = GREATEST(expiry, NOW() + %s)
            WHERE id = %s
            RETURNING uploaded, expiry, (SELECT name FROM storage_pools WHERE id = files.pool)
            """,
            (ttl, id),
        )
        row = cur.fetchone()

        size = None
        if row:
            uploaded, expiry, pool_name = row
            try:
                size = files.get_file_path(pool_name, id).stat().st_size
            except FileNotFoundError:
                app.logger.warning(f"File {id} in database not found on disk!")
                row = None

        if not row:
            app.logger.debug("File '{}' does not exist".format(id))
            return error_resp(http.NOT_FOUND)

        return json_resp(
            {"size": size, "uploaded": uploaded.timestamp(), "expires": expiry.timestamp()}
        )


@app.get("/session_version")
def get_session_version():
    platform = request.args.get("platform")

    if platform not in ("desktop", "android", "ios"):
        app.logger.warning("Invalid session platform '{}'".format(platform))
        return error_resp(http.NOT_FOUND)
    project = "session-foundation/session-" + platform

    # Available release channels are 'stable', 'prerelease' and 'alpha'
    channel = request.args.get("release_channel", "stable")

    # If we were provided with auth headers then validate the authentication (if they weren't provided
    # then just continue as usual for backwards compatibility)
    blinded_id = valid_blinded_version_id_for_auth(request, False)

    if blinded_id is not None:
        with db.psql.transaction(), db.psql.cursor() as cur:
            cur.execute(
                """
                INSERT INTO account_version_checks (blinded_id, platform, channel, timestamp)
                VALUES (%s, %s, %s, NOW())""",
                (blinded_id, platform, channel),
            )

    with db.psql.cursor() as cur:
        # Validate the project exists and retrieve when it was last updated
        cur.execute("SELECT updated FROM projects WHERE name = %s", (project,))
        row = cur.fetchone()
        if row is None:
            app.logger.warning("{} does not exist!".format(project))
            return error_resp(http.BAD_GATEWAY)

        updated = row[0]

        # Fetch the latest version
        cur.execute(
            """
            SELECT id, vmajor, vminor, vpatch, valpha, version, name, notes
            FROM versions
            WHERE proj_name = %s AND channel = %s
            ORDER BY vmajor DESC, vminor DESC, vpatch DESC, valpha DESC NULLS LAST
            """,
            (project, channel),
        )

        row = cur.fetchone()
        if row is None:
            app.logger.warning("{} has no {} releases!".format(project, channel))
            return error_resp(http.BAD_GATEWAY)

        release_id = row[0]
        release_version = row[5]

        response = {"status_code": 200, "updated": updated, "result": release_version}

        if row[6]:
            response["name"] = row[6]

        if row[7]:
            response["notes"] = row[7]

        # Add release assets
        cur.execute(
            """
            SELECT name, url FROM release_assets
            WHERE release = %s""",
            (release_id,),
        )
        assets = cur.fetchall()

        if assets:
            asset_info = []

            for asset in assets:
                asset_info.append({"name": asset[0], "url": asset[1]})

            response["assets"] = asset_info

        # Add prerelease info if present
        cur.execute(
            """
            SELECT id, vmajor, vminor, vpatch, valpha, version, name, notes
            FROM versions
            WHERE proj_name = %s AND channel = 'prerelease'
            ORDER BY vmajor DESC, vminor DESC, vpatch DESC, valpha DESC NULLS LAST""",
            (project,),
        )

        row = cur.fetchone()
        if row is not None:
            prerelease_id = row[0]
            prerelease_version = row[5]

            response["prerelease"] = {"result": prerelease_version, "updated": updated}

            if row[6]:
                response["prerelease"]["name"] = row[6]

            if row[7]:
                response["prerelease"]["notes"] = row[7]

            # Add prerelease assets
            cur.execute(
                """
                SELECT name, url FROM release_assets
                WHERE release = %s""",
                (prerelease_id,),
            )
            assets = cur.fetchall()

            if assets:
                asset_info = []

                for asset in assets:
                    asset_info.append({"name": asset[0], "url": asset[1]})

                response["prerelease"]["assets"] = asset_info

        return json_resp(response)


@app.get("/token_info")
def get_token_info():
    days = request.args.get("days")

    try:
        days = int(days)
    except (TypeError, ValueError):
        days = None

    # Default to 7 if 'days' is None or it outside of the accepted range
    if days is None or not (1 <= days <= 30):
        days = 7

    with db.psql.cursor() as cur:
        cur.execute(
            """
            SELECT maximum_supply, sent_per_node, staking_reward_pool FROM session_token_stats
            """
        )
        stats = cur.fetchone()
        if stats is None:
            app.logger.warning("No token stats available!")
            return error_resp(http.BAD_GATEWAY)

        cur.execute(
            """
            SELECT current_value, circulating_supply, total_nodes, updated FROM session_token_history
            WHERE updated >= date_trunc('day', NOW()) - INTERVAL '%s DAY'
            """,
            (days,),
        )
        rows = cur.fetchall()
        columns = ["current_value", "circulating_supply", "total_nodes", "updated"]
        history = [dict(zip(columns, row)) for row in rows]

        return json_resp(
            {
                "status_code": 200,
                "info": {
                    "maximum_supply": stats[0],
                    "sent_per_node": stats[1],
                    "staking_reward_pool": stats[2],
                    "history": history,
                },
            }
        )
