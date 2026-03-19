import pytest
import reporterman.database.database as db
from reporterman.database.database import (
    init_db,
    insert_target,
    get_target,
    insert_software,
    get_software,
    get_target_id,
    get_vulnerability,
    insert_vulnerability,
    update_vulnerability,
    get_vulnerability_id,
    insert_exploit,
    get_exploit,
    insert_attemp,
    get_exploit_id,
    get_attemp,
)


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """
    TEMP DB PATH
    """
    db_file = tmp_path / "test.db"
    monkeypatch.setattr(db, "DB_PATH", str(db_file))
    init_db()
    insert_target("192.168.1.11", ["linux", "linux_kernel", "2.6", "info"])  # noqa

    return db_file


def test_insert_and_get_target(temp_db):
    target = "192.168.1.10"
    target_info = ["linux", "linux_kernel", "2.6", "lorem ipsum"]

    # Test
    insert_target(target, target_info)
    result = get_target(target)

    assert result is not None
    assert len(result) == 1

    row = result[0]

    # sqlite3.Row is managed as a dict
    assert row["ip_addr"] == target
    assert row["vendor"] == target_info[0]
    assert row["product"] == target_info[1]
    assert row["version"] == target_info[2]
    assert row["other_info"] == target_info[3]


def test_get_target_id(temp_db):
    result = get_target_id("192.168.1.11")
    assert result is not None
    assert result == 1


def test_insert_and_get_software(temp_db):
    soft = ["product", "version", "other_info", "port"]

    # Test
    insert_software(1, soft, False)
    result = get_software(1, soft[3])

    assert result is not None
    assert len(result) == 1

    row = result[0]

    # sqlite3.Row is managed as a dict
    assert row["port"] == soft[3]
    assert row["product"] == soft[0]
    assert row["version"] == soft[1]
    assert row["other_info"] == soft[2]
    assert row["obsolete"] == 0


def test_insert_update_and_get_vuln(temp_db):
    vuln = ["cve", "https://link"]
    # Test
    insert_vulnerability(1, vuln, "lorem ipsum")
    result = get_vulnerability(1, vuln[0])

    assert result is not None
    assert len(result) == 1

    row = result[0]

    # sqlite3.Row is managed as a dict
    assert row["cve"] == vuln[0]
    assert row["link"] == vuln[1]
    assert row["description"] == "lorem ipsum"
    assert row["exploited"] == 0

    update_vulnerability(1)
    result = get_vulnerability(1, vuln[0])

    assert result is not None
    assert len(result) == 1

    row = result[0]

    # sqlite3.Row is managed as a dict
    assert row["cve"] == vuln[0]
    assert row["link"] == vuln[1]
    assert row["description"] == "lorem ipsum"
    assert row["exploited"] == 1


def test_get_vuln_id(temp_db):
    vuln = ["cve", "https://link"]
    insert_vulnerability(1, vuln, "lorem ipsum")

    # Test
    result = get_vulnerability_id(1, vuln[0])
    assert result is not None
    assert result == 1


def test_insert_and_get_exploit(temp_db):
    vuln = ["cve", "https://link"]
    insert_vulnerability(1, vuln, "lorem ipsum")
    exploit = "exploit1"
    # Test
    insert_exploit(1, exploit)
    result = get_exploit(1, exploit)

    assert result is not None
    assert len(result) == 1

    row = result[0]

    # sqlite3.Row is managed as a dict
    assert row["name"] == exploit

def test_insert_and_get_attemp(temp_db):
    target = "192.168.1.101"
    target_info = ["linuxxx", "linux_kernel", "2.6", "lorem ipsum"]
    insert_target(target, target_info)
    target_id = get_target_id(target)
    vuln = ["cvee", "https://link"]
    insert_vulnerability(target_id, vuln, "lorem ipsum")
    vuln_id = get_vulnerability_id(target_id, vuln[0])
    exploit = "exploit10"
    insert_exploit(vuln_id, exploit)
    # Test
    attemp = ["payload", 1, "cvee"]
    insert_attemp(target, exploit, attemp)
    exploit_id = get_exploit_id(exploit, "cvee", target)
    result = get_attemp(exploit_id, "payload")

    assert result is not None
    assert len(result) == 1
    
    row = result[0]

    assert row["payload"] == "payload"
    assert row["success"] == True
