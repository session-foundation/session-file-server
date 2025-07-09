from .web import app
from . import db
from . import config
from . import files
from .timer import timer

import re
from datetime import datetime
import requests


def _expire_files():
    removed = 0
    with db.psql.cursor() as cur:
        for t in ['files'] if config.BACKUP_TABLE is None else ['files', config.BACKUP_TABLE]:
            # We do the deletion with a transaction held so that, if we fail to delete from disk
            # (for instance, if we are killed during the deletion or get an IO error) the
            # transaction reverts so that the IDs still exist, and we can try deleting them again.
            # (It won't break anything if the file doesn't exist on disk, but an unreferenced file
            # on disk would stay around indefinitely).
            with db.psql.transaction():
                cur.execute(f"DELETE FROM {t} WHERE expiry <= NOW() RETURNING id, data IS NULL")
                for id, is_stored in cur:
                    removed += 1
                    if is_stored:
                        p = files.get_file_path(id)
                        p.unlink(missing_ok=True)

    if removed > 0:
        app.logger.info(f"Deleted {removed} expired files")


def _update_versions():
    with db.psql.cursor() as cur:
        # NB: we do this infrequently (once every 30 minutes, per project) because Github rate
        # limits if you make more than 60 requests in an hour.
        # Limit to 1 because, if there are more than 1 outdated, it doesn't hurt anything to delay
        # the next one by 30 seconds (and avoids triggering github rate limiting).
        cur.execute(
            """
            SELECT id, name FROM projects
            WHERE updated < NOW() + '30 minutes ago' LIMIT 1
            """
        )
        row = cur.fetchone()
        if row:
            projid, project = row
            latest = requests.get(
                f"https://api.github.com/repos/{project}/releases/latest", timeout=5
            ).json()

            # If the latest release doesn't have version information then don't bother continuing
            # this means something is invalid, or we were rate limited
            if 'tag_name' not in latest:
                app.logger.warning(
                    f"'tag_name' key not found in latest release for project {project}"
                )
                return

            recent = requests.get(
                f"https://api.github.com/repos/{project}/releases?per_page=3", timeout=5
            ).json()

            with db.psql.transaction():
                for release in recent:
                    v = release["tag_name"]
                    vresult = re.match(
                        r'v?(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:-(alpha|beta)\.(\d+))?$', v
                    )
                    if not vresult:
                        app.logger.warning(
                            f"Unknown {project} tag does not look like a x.y.z or x.y.z-alpha.b version: {v}'"
                        )
                        return

                    vmajor = int(vresult.group(1))
                    vminor = int(vresult.group(2))
                    vpatch = int(vresult.group(3))
                    valpha = (
                        int(vresult.group(5))
                        if vresult.group(4) == 'alpha' and vresult.group(5)
                        else None
                    )

                    cur.execute(
                        """
                        INSERT INTO releases (project, prerelease, vmajor, vminor, vpatch, valpha, url, name, notes)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT(project, vmajor, vminor, vpatch, valpha) DO UPDATE SET
                            prerelease = EXCLUDED.prerelease,
                            url = EXCLUDED.url,
                            name = EXCLUDED.name,
                            notes = EXCLUDED.notes
                            WHERE releases.prerelease != EXCLUDED.prerelease
                                OR releases.url != EXCLUDED.url
                                OR releases.name != EXCLUDED.name
                                OR releases.notes != EXCLUDED.notes
                            RETURNING id
                        """,
                        (
                            projid,
                            bool(release.get("prerelease")),
                            vmajor,
                            vminor,
                            vpatch,
                            valpha,
                            release.get("html_url"),
                            release.get("name"),
                            release.get("body"),
                        ),
                    )
                    row = cur.fetchone()
                    if row:
                        relid = row[0]
                        # We either inserted or updated the row, so clear any assets and
                        # readd them (in case the upload assets changed)
                        cur.execute("DELETE FROM release_assets WHERE release = %s", (relid,))
                        for asset in release.get('assets', []):
                            cur.execute(
                                "INSERT INTO release_assets (release, name, url) VALUES (%s, %s, %s)",
                                (relid, asset['name'], asset['url']),
                            )

                cur.execute("UPDATE projects SET updated = NOW() WHERE id = %s", (projid,))


@timer(5, target="worker1")
def periodic(signum):
    with app.app_context():
        _expire_files()
        _update_versions()
