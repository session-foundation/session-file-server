from . import config
from .web import app
from . import db
from . import http, utils

import flask
from flask import request, abort, Response
import secrets
from base64 import urlsafe_b64encode
from hashlib import blake2b
import json
from decimal import Decimal
from datetime import datetime
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
    return flask.Response(json.dumps(data, cls=CustomEncoder), status=status, mimetype="application/json")


def error_resp(code):
    """
    Simple JSON error response to send back, embedded as `status_code` and also as the HTTP response
    code.
    """
    return json_resp({"status_code": code}, code)


def generate_file_id(data):
    """
    Generate a file ID by blake2b hashing the file body, then using a 33-byte digest encoded into 44
    base64 chars.  (Ideally would be 32, but that would result in base64 padding, so increased to 33
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
                http.BAD_REQUEST, "Invalid authentication: one or more X-FS-* auth headers is missing")
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
    to_verify = (
        ts_str.encode()
        + request.method.encode()
        + request.path.encode()
    )

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


@app.post("/file")
def submit_file(*, body=None, deprecated=False):
    if body is None:
        body = request.data

    if not 0 < len(body) <= config.MAX_FILE_SIZE:
        app.logger.warn(
            "Rejecting upload of size {} ∉ (0, {}]".format(len(body), config.MAX_FILE_SIZE)
        )
        return error_resp(http.PAYLOAD_TOO_LARGE)

    id = None
    try:
        if config.BACKWARDS_COMPAT_IDS:
            done = False
            for attempt in range(25):

                id = BACKWARDS_COMPAT_MSB << BACKWARDS_COMPAT_RANDOM_BITS | secrets.randbits(
                    BACKWARDS_COMPAT_RANDOM_BITS
                )
                if not deprecated:
                    id = str(id)  # New ids are always strings; legacy requests require an integer
                try:
                    with db.psql.cursor() as cur:
                        cur.execute(
                            "INSERT INTO files (id, data, expiry) VALUES (%s, %s, NOW() + %s)",
                            (id, body, config.FILE_EXPIRY),
                        )
                except psycopg.errors.UniqueViolation:
                    continue

                if db.slave:
                    try:
                        with db.slave.cursor() as cur:
                            cur.execute(
                                "INSERT INTO files (id, data, expiry) VALUES (%s, %s, NOW() + %s)",
                                (id, body, config.FILE_EXPIRY),
                            )
                    except psycopg.errors.Error as e:
                        app.logger.warning(f"Failed to store file on slave: {e}")
                        pass

                done = True
                break

            if not done:
                app.logger.error(
                    "Tried 25 random IDs and got all constraint failures, something getting wrong!"
                )
                return error_resp(http.INSUFFICIENT_STORAGE)

        else:
            id = generate_file_id(body)
            for psql in (db.psql, db.slave):
                if not psql:
                    continue

                with psql.transaction(), psql.cursor() as cur:
                    try:
                        # Don't pass the data yet because we might be de-duplicating
                        with db.psql.transaction():
                            cur.execute(
                                "INSERT INTO files (id, data, expiry) VALUES (%s, '', NOW() + %s)",
                                (id, config.FILE_EXPIRY),
                            )
                    except psycopg.errors.UniqueViolation:
                        # Found a duplicate id, so de-duplicate by just refreshing the expiry
                        cur.execute(
                            "UPDATE files SET uploaded = NOW(), expiry = NOW() + %s WHERE id = %s",
                            (config.FILE_EXPIRY, id),
                        )
                    else:
                        cur.execute("UPDATE files SET data = %s WHERE id = %s", (body, id))

    except Exception as e:
        app.logger.error("Failed to insert file: {}".format(e))
        return error_resp(http.INTERNAL_SERVER_ERROR)

    response = {"result": id, "status_code": 200} if deprecated else {"id": id}
    return json_resp(response)


@app.post("/files")
def submit_file_old():
    input = request.json
    if input is None or "file" not in input:
        app.logger.warn("Invalid request: did not find json with a 'file' property")
        return error_resp(http.BAD_REQUEST)

    body = input["file"]
    if not 0 < len(body) <= config.MAX_FILE_SIZE_B64:
        app.logger.warn(
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
        cur.execute("SELECT data FROM files WHERE id = %s", (id,), binary=True)
        row = cur.fetchone()
        if not row and config.BACKUP_TABLE is not None:
            cur.execute(f"SELECT data FROM {config.BACKUP_TABLE} WHERE id = %s", (id,), binary=True)
            row = cur.fetchone()
        if row:
            response = flask.make_response(row[0])
            response.headers.set("Content-Type", "application/octet-stream")
            return response
        else:
            app.logger.warn("File '{}' does not exist".format(id))
            return error_resp(http.NOT_FOUND)


@app.get("/files/<id>")
def get_file_old(id):
    with db.psql.cursor() as cur:
        cur.execute("SELECT data FROM files WHERE id = %s", (id,), binary=True)
        row = cur.fetchone()
        if not row and config.BACKUP_TABLE is not None:
            cur.execute(f"SELECT data FROM {config.BACKUP_TABLE} WHERE id = %s", (id,), binary=True)
            row = cur.fetchone()
        if row:
            return json_resp({"status_code": 200, "result": utils.encode_base64(row[0])})
        else:
            app.logger.warn("File '{}' does not exist".format(id))
            return error_resp(http.NOT_FOUND)


@app.get("/file/<id>/info")
def get_file_info(id):
    with db.psql.cursor() as cur:
        cur.execute("SELECT length(data), uploaded, expiry FROM files WHERE id = %s", (id,))
        row = cur.fetchone()
        if not row and config.BACKUP_TABLE is not None:
            cur.execute(f"SELECT length(data), uploaded, expiry FROM {config.BACKUP_TABLE} WHERE id = %s", (id,))
            row = cur.fetchone()
        if row:
            return json_resp(
                {"size": row[0], "uploaded": row[1].timestamp(), "expires": row[2].timestamp()}
            )
        else:
            app.logger.warn("File '{}' does not exist".format(id))
            return error_resp(http.NOT_FOUND)


@app.get("/session_version")
def get_session_version():
    platform = request.args.get("platform")

    if platform not in ("desktop", "android", "ios"):
        app.logger.warn("Invalid session platform '{}'".format(platform))
        return error_resp(http.NOT_FOUND)
    project = "session-foundation/session-" + platform

    # If we were provided with auth headers then validate the authentication (if they weren't provided
    # then just continue as usual for backwards compatibility)
    blinded_id = valid_blinded_version_id_for_auth(request, False)

    if blinded_id is not None:
        for psql in (db.psql, db.slave):
            if not psql:
                continue

            with psql.transaction(), psql.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO account_version_checks (blinded_id, platform, timestamp)
                    VALUES (%s, %s, NOW())""",
                    (blinded_id, platform),
                )

    with db.psql.cursor() as cur:
        # Validate the project exists and retrieve when it was last updated
        cur.execute("SELECT updated from projects WHERE name = %s", (project,),)

        row = cur.fetchone()
        if row is None:
            app.logger.warn("{} does not exist!".format(project))
            return error_resp(http.BAD_GATEWAY)

        updated = row[0]

        # Fetch the latest release version
        cur.execute(
            """
            SELECT id, version, name, notes from release_versions
            WHERE proj_name = %s ORDER BY version_code DESC""",
            (project,),
        )

        row = cur.fetchone()
        if row is None:
            app.logger.warn("{} has no releases!".format(project))
            return error_resp(http.BAD_GATEWAY)

        release_id = row[0]
        response = {
            "status_code": 200,
            "updated": updated,
            "result": row[1]
        }

        if row[2]:
            response["name"] = row[2]

        if row[3]:
            response["notes"] = row[3]

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
                asset_info.append({
                    "name": asset[0],
                    "url": asset[1]
                })
                
            response["assets"] = asset_info

        # Add prerelease info if present
        cur.execute(
            """
            SELECT id, version, name, notes from prerelease_versions
            WHERE proj_name = %s ORDER BY version_code DESC""",
            (project,),
        )

        row = cur.fetchone()
        if row is not None:
            prerelease_id = row[0]
            response["prerelease"] = {
                "result": row[1],
                "updated": updated,
            }

            if row[2]:
                response["prerelease"]["name"] = row[2]

            if row[3]:
                response["prerelease"]["notes"] = row[3]

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
                    asset_info.append({
                        "name": asset[0],
                        "url": asset[1]
                    })
                    
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
            """,
        )
        stats = cur.fetchone()
        if stats is None:
            app.logger.warn("No token stats available!")
            return error_resp(http.BAD_GATEWAY)

        cur.execute(
            """
            SELECT current_value, circulating_supply, total_nodes, updated FROM session_token_history
            WHERE updated >= date_trunc('day', NOW()) - INTERVAL '%s DAY'
            """,
            (days,)
        )
        rows = cur.fetchall()
        columns = ["current_value", "circulating_supply", "total_nodes", "updated"]
        history = [dict(zip(columns, row)) for row in rows]

        return json_resp({
            "status_code": 200,
            "info": {
                "maximum_supply": stats[0],
                "sent_per_node": stats[1],
                "staking_reward_pool": stats[2],
                "history": history
            }
        })
