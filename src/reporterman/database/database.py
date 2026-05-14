import sqlite3
from pathlib import Path
from datetime import date
from reporterman.database.models import (
    CREATE_TARGET_TABLE,
    CREATE_SOFTWARE_TABLE,
    CREATE_VULNERABILITY_TABLE,
    CREATE_EXPLOIT_TABLE,
    CREATE_ATTEMP_TABLE,
    CREATE_STATS_TABLE,
    CREATE_AUDIT_TABLE,
    DROP_AUDIT,
    DROP_TARGET,
    DROP_EXPLOIT,
    DROP_ATTEMP,
    DROP_VULNERABILITY,
    DROP_SOFTWARE,
    DROP_STATS,
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
        connect.execute(DROP_EXPLOIT)
        connect.execute(DROP_VULNERABILITY)
        connect.execute(DROP_SOFTWARE)
        connect.execute(DROP_TARGET)
        connect.execute(DROP_ATTEMP)
        connect.execute(DROP_STATS)
        connect.execute(DROP_AUDIT)
        connect.execute(CREATE_AUDIT_TABLE)
        connect.execute(CREATE_STATS_TABLE)
        connect.execute(CREATE_TARGET_TABLE)
        connect.execute(CREATE_SOFTWARE_TABLE)
        connect.execute(CREATE_VULNERABILITY_TABLE)
        connect.execute(CREATE_EXPLOIT_TABLE)
        connect.execute(CREATE_ATTEMP_TABLE)


def drop_db() -> None:
    with get_connection() as connect:
        connect.execute(DROP_EXPLOIT)
        connect.execute(DROP_VULNERABILITY)
        connect.execute(DROP_SOFTWARE)
        connect.execute(DROP_TARGET)
        connect.execute(DROP_ATTEMP)
        connect.execute(DROP_STATS)


def insert_value(insert_cmd: str, params: tuple) -> None:
    with get_connection() as connect:
        connect.execute(insert_cmd, params)


def get_value(get_cmd: str) -> None:
    with get_connection() as connect:
        ex = connect.execute(get_cmd)
        return ex.fetchall()


# fmt: off
def create_audit():
    now = date.today().isoformat()
    insert_cmd = """
    INSERT INTO audit (date) VALUES (?)
    """
    params = (now,)
    insert_value(insert_cmd, params)


def insert_target(target: str, target_info: list) -> None:
    insert_cmd = """
    INSERT INTO target (
        ip_addr,
        vendor,
        product,
        version,
        other_info,
        audit_id
    ) VALUES (?, ?, ?, ?, ?, ?);
    """

    params = (
        target,
        target_info[0],
        target_info[1],
        target_info[2],
        target_info[3],
        1
    )
    insert_value(insert_cmd, params)


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
    insert_cmd = """
    INSERT INTO software (
        product,
        version,
        other_info,
        port,
        obsolete,
        target_id
    ) VALUES (?, ?, ?, ?, ?, ?);
    """

    params = (
        soft[0],
        soft[1],
        soft[2],
        soft[3],
        obs,
        target
    )
    insert_value(insert_cmd, params)


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


def get_target_ports(target_id: int) -> list:
    get_cmd = f"""
    SELECT port
    FROM software
    WHERE target_id = {target_id};
    """
    total = get_value(get_cmd)
    return [row[0] for row in total]


def insert_vulnerability(target: int, vuln: list, desc: str) -> None:  # noqa
    insert_cmd = """
    INSERT INTO vulnerability (
        cve,
        link,
        description,
        exploited,
        target_id
    ) VALUES (?, ?, ?, ?, ?);
    """

    params = (
        vuln[0],
        vuln[1],
        desc,
        False,
        target
    )
    insert_value(insert_cmd, params)


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
    update_cmd = """
    UPDATE vulnerability
    SET exploited = TRUE
    WHERE id = ?;
    """

    params = (vuln,)
    insert_value(update_cmd, params)


def get_target_cves(target_id: int) -> list:
    get_cmd = f"""
    SELECT cve
    FROM vulnerability
    WHERE target_id = {target_id};
    """
    total = get_value(get_cmd)
    return [row[0] for row in total]


def get_vulnerability_id(target_id: int, cve: str) -> int:
    get_cmd = f"""
    SELECT v.id
    FROM vulnerability v
    WHERE
    v.target_id = {target_id}
    AND
    v.cve = '{cve}';
    """
    id = get_value(get_cmd)
    id = id[0]["id"]
    return id


def insert_exploit(vuln_id: int, exploit: str) -> None:
    insert_cmd = """
    INSERT INTO exploit (
        name,
        vuln_id
    ) VALUES (?, ?);
    """

    params = (
        exploit,
        vuln_id
    )
    insert_value(insert_cmd, params)


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


def get_exp_vuln(vuln_id: int) -> list:
    get_cmd = f"""
    SELECT name
    FROM exploit
    WHERE vuln_id = {vuln_id};
    """
    total = get_value(get_cmd)
    return [row[0] for row in total]


def get_exploit_id_short(name: str, vuln_id: int) -> int:
    get_cmd = f"""
    SELECT e.id
    FROM exploit e
    WHERE
    e.vuln_id = {vuln_id}
    AND
    e.name = '{name}';
    """
    id = get_value(get_cmd)
    id = id[0]["id"]
    return id


def get_exploit_id(name: str, cve: str, target: str) -> int:
    target_id = get_target_id(target)
    vuln_id = get_vulnerability_id(target_id, cve)
    get_cmd = f"""
    SELECT e.id
    FROM exploit e
    WHERE
    e.vuln_id = {vuln_id}
    AND
    e.name = '{name}';
    """
    id = get_value(get_cmd)
    id = id[0]["id"]
    return id


def insert_attemp(target: str, name: str, exec: list) -> None:
    exploit_id = get_exploit_id(name, exec[2], target)
    insert_cmd = """
    INSERT INTO attemp (
        payload,
        success,
        exploit_id
    ) VALUES (?, ?, ?);
    """

    params = (
        exec[0],
        exec[1],
        exploit_id
    )
    insert_value(insert_cmd, params)


# For test purposes
def get_attemp(exploit_id, payload) -> dict:
    get_cmd = f"""
    SELECT *
    FROM attemp a
    WHERE
    a.exploit_id = {exploit_id}
    AND
    a.payload = '{payload}';
    """
    attemp = get_value(get_cmd)
    return attemp


def get_attemps(exploit_id) -> list:
    get_cmd = f"""
    SELECT *
    FROM attemp
    WHERE
    exploit_id = {exploit_id}
    """
    attemp = get_value(get_cmd)
    return attemp


def insert_llm_stats(drift: int, total_attemps: int, fail_rate: float) -> None:
    insert_cmd = """
    INSERT INTO stats (
        model_drift,
        total_attemps,
        fail_rate,
        audit_id
    ) VALUES (?, ?, ?, ?);
    """

    params = (
        drift,
        total_attemps,
        fail_rate,
        1
    )
    insert_value(insert_cmd, params)


# There is only 1 item always
def get_llm_stats() -> dict:
    get_cmd = """
    SELECT *
    FROM stats s
    WHERE s.id = 1;
    """
    stats = get_value(get_cmd)
    return stats


def get_n_targets() -> int:
    get_cmd = """
    SELECT COUNT(*)
    FROM target;
    """
    count = get_value(get_cmd)
    total = count[0][0]
    return total


def get_n_software() -> int:
    get_cmd = """
    SELECT COUNT(*)
    FROM software;
    """
    count = get_value(get_cmd)
    total = count[0][0]
    return total


def get_n_vuln() -> int:
    get_cmd = """
    SELECT COUNT(*)
    FROM vulnerability;
    """
    count = get_value(get_cmd)
    total = count[0][0]
    return total


def get_n_exploited_vuln() -> int:
    get_cmd = """
    SELECT COUNT(*)
    FROM vulnerability
    WHERE exploited = TRUE;
    """
    count = get_value(get_cmd)
    total = count[0][0]
    return total


def get_n_software_by_t(target_id: int) -> int:
    get_cmd = f"""
    SELECT COUNT(*)
    FROM software
    WHERE target_id = {target_id};
    """
    count = get_value(get_cmd)
    total = count[0][0]
    return total


def get_n_vuln_by_t(target_id: int) -> int:
    get_cmd = f"""
    SELECT COUNT(*)
    FROM vulnerability
    WHERE target_id = {target_id};
    """
    count = get_value(get_cmd)
    total = count[0][0]
    return total


def get_n_exploited_by_t(target_id: int) -> int:
    get_cmd = f"""
    SELECT COUNT(*)
    FROM vulnerability
    WHERE target_id = {target_id}
    AND exploited = TRUE;
    """
    count = get_value(get_cmd)
    total = count[0][0]
    return total


def get_targets_ip() -> list:
    get_cmd = """
    SELECT ip_addr
    FROM target;
    """
    total = get_value(get_cmd)
    return [row[0] for row in total]
# fmt: on
