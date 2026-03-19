CREATE_TARGET_TABLE = """
CREATE TABLE IF NOT EXISTS target (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_addr TEXT NOT NULL UNIQUE,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        version TEXT NOT NULL,
        other_info TEXT NOT NULL
);
"""


CREATE_SOFTWARE_TABLE = """
CREATE TABLE IF NOT EXISTS software (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        product TEXT NOT NULL,
        version TEXT NOT NULL,
        other_info TEXT NOT NULL,
        port TEXT NOT NULL,
        obsolete BOOL NOT NULL,

        FOREIGN KEY(target_id)
            REFERENCES target (id)
            ON DELETE CASCADE
);
"""


CREATE_VULNERABILITY_TABLE = """
CREATE TABLE IF NOT EXISTS vulnerability (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        cve TEXT NOT NULL,
        link TEXT,
        description TEXT NOT NULL,
        exploited BOOL NOT NULL,

        FOREIGN KEY(target_id)
            REFERENCES target (id)
            ON DELETE CASCADE
);
"""


CREATE_EXPLOIT_TABLE = """
CREATE TABLE IF NOT EXISTS exploit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vuln_id INTEGER NOT NULL,
        name TEXT NOT NULL,

        FOREIGN KEY(vuln_id)
            REFERENCES vulnerability (id)
            ON DELETE CASCADE
);
"""


CREATE_ATTEMP_TABLE = """
CREATE TABLE IF NOT EXISTS attemp (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exploit_id INTEGER NOT NULL,
        payload TEXT,
        success BOOL NOT NULL,

        FOREIGN KEY(exploit_id)
            REFERENCES exploit (id)
            ON DELETE CASCADE
);
"""


DROP_EXPLOIT = """
DROP TABLE IF EXISTS exploit;
"""


DROP_SOFTWARE = """
DROP TABLE IF EXISTS software;
"""


DROP_TARGET = """
DROP TABLE IF EXISTS target;
"""


DROP_VULNERABILITY = """
DROP TABLE IF EXISTS vulnerability;
"""

DROP_ATTEMP = """
DROP TABLE IF EXISTS attemp;
"""
