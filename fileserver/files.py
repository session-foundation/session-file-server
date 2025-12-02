from . import config
from pathlib import Path

BASE_PATH = Path(config.FILE_BASE_PATH)
if not BASE_PATH.is_absolute():
    BASE_PATH = BASE_PATH.absolute()


def get_file_path(pool: str, id: int | str) -> Path:
    """
    Takes a pool and file ID and returns the path (with subdirectory prefix) where the file should be stored.
    """
    if isinstance(id, str) and len(id) == 44:
        prefix = id[0:2]
    else:
        if not isinstance(id, int):
            id = int(id)
        prefix = "{:03d}".format(id % 1000)

    return BASE_PATH / pool / prefix / f"{id}"


def store(pool: str, id: int | str, body: bytes):
    """
    Stores a file into the configured storage directory, creating the directory prefix (if needed).
    """

    store = get_file_path(pool, id)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_bytes(body)
