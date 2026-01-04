import sqlite3
from pathlib import Path
from reporterman.database.models import (
    CREATE_TARGET_TABLE,
    CREATE_SOFTWARE_TABLE,
    CREATE_VULNERABILITY_TABLE,
    CREATE_EXPLOIT_TABLE,
)

DB_BASE_DIR = Path(__file__).resolve().parent
DB_PATH = DB_BASE_DIR / "reporterman.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row  # Manage outputs as "dicts"
    connection.execute("PRAGMA foreign_keys = ON;")
    return connection


def init_db() -> None:
    with get_connection() as connect:
        connect.execute(CREATE_TARGET_TABLE)
        connect.execute(CREATE_SOFTWARE_TABLE)
        connect.execute(CREATE_VULNERABILITY_TABLE)
        connect.execute(CREATE_EXPLOIT_TABLE)


def insert_value(insert_cmd: str) -> None:
    with get_connection() as connect:
        connect.execute(insert_cmd)


def get_value(get_cmd: str) -> None:
    with get_connection() as connect:
        ex = connect.execute(get_cmd)
        return ex.fetchall()


# fmt: off
def insert_target(target: str, target_info: list) -> None:
    cmd = f"""
    INSERT INTO target (
            ip_addr,
            vendor,
            product,
            version,
            other_info
            ) VALUES (
                    '{target}',
                    '{target_info[0]}',
                    '{target_info[1]}',
                    '{target_info[2]}',
                    '{target_info[3]}'
            );
    """
    insert_value(cmd)


# Now is for test purposes only
def get_target(target: str) -> dict:
    get_cmd = f"""
    SELECT *
    FROM target t
    WHERE t.ip_addr = '{target}';
    """
    target = get_value(get_cmd)
    return target


def get_target_id(target: str) -> int:
    get_cmd = f"""
    SELECT t.id
    FROM target t
    WHERE t.ip_addr = '{target}';
    """
    id = get_value(get_cmd)
    id = id[0]["id"]
    return id


# Now is for test purposes only
def insert_software(target: int, soft: list, obs: bool) -> None:
    insert_cmd = f"""
    INSERT INTO software (
            product,
            version,
            other_info,
            port,
            obsolete,
            target_id) VALUES (
                    '{soft[0]}',
                    '{soft[1]}',
                    '{soft[2]}',
                    '{soft[3]}',
                    {obs},
                    {target}
                    );
    """
    insert_value(insert_cmd)


def get_software(target: int, port: str) -> dict:
    get_cmd = f"""
    SELECT *
    FROM software s
    WHERE
    s.target_id = {target}
    AND
    s.port = '{port}';
    """
    software = get_value(get_cmd)
    return software


def insert_vulnerability(target: int, vuln: list, desc: str) -> None:  # noqa
    insert_cmd = f"""
    INSERT INTO vulnerability (
            cve,
            link,
            description,
            exploited,
            target_id) VALUES (
                    '{vuln[0]}',
                    '{vuln[1]}',
                    '{desc}',
                    FALSE,
                    {target}
                    );
    """
    insert_value(insert_cmd)


def get_vulnerability(target: int, cve: str) -> dict:
    get_cmd = f"""
    SELECT *
    FROM vulnerability v
    WHERE
    v.target_id = {target}
    AND
    v.cve = '{cve}';
    """
    vulnerability = get_value(get_cmd)
    return vulnerability


def update_vulnerability(vuln: int) -> None:
    update_cmd = f"""
    UPDATE vulnerability
    SET exploited = TRUE
    WHERE
    id = {vuln};
    """
    insert_value(update_cmd)


def get_vulnerability_id(target: int, cve: str) -> int:
    get_cmd = f"""
    SELECT v.id
    FROM vulnerability v
    WHERE
    v.target_id = {target}
    AND
    v.cve = '{cve}';
    """
    id = get_value(get_cmd)
    id = id[0]["id"]
    return id


def insert_exploit(vuln: int, exploit: list) -> None:
    insert_cmd = f"""
    INSERT INTO exploit (
        name,
        source,
        payload,
        success,
        vuln_id) VALUES (
                '{exploit[0]}',
                '{exploit[1]}',
                '{exploit[2]}',
                FALSE,
                {vuln});
    """
    insert_value(insert_cmd)


def get_exploit(vuln: int, name: str) -> dict:
    get_cmd = f"""
    SELECT *
    FROM exploit e
    WHERE
    e.vuln_id = {vuln}
    AND
    e.name = '{name}';
    """
    exploit = get_value(get_cmd)
    return exploit


def update_exploit(vuln: int, name: str) -> None:
    update_cmd = f"""
    UPDATE exploit
    SET success = TRUE
    WHERE
    vuln_id = {vuln}
    AND
    name = '{name}';
    """
    insert_value(update_cmd)
# fmt: on
