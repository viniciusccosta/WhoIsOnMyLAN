import sqlite3
from datetime import datetime

# ==============================================================================================
database_path = None

# ==============================================================================================
def createDatabase(db_path):
    global database_path
    database_path = db_path

    db = sqlite3.connect(db_path)
    db.execute(
        """
            CREATE TABLE IF NOT EXISTS HOST (
                mac         TEXT PRIMARY KEY,
                ipv4        TEXT,
                timestamp   DATETIME,
                name        TEXT,
                known       BOOL
            );
        """
    )
    db.close()

# ==============================================================================================
# TABLE HOST:
from host import Host

def getAllHosts():
    """
    Method responsable to retrieve all hosts from database.

    :return: A dictionary with all hosts once founded.
    """

    hosts = []

    db = sqlite3.connect(database_path)
    sql = "SELECT mac, ipv4, timestamp, name, known FROM HOST;"
    cur = db.cursor()
    cur.execute(sql)

    for r in cur.fetchall():

        hosts.append(
            Host(
                mac       = r[0],
                ipv4      = r[1],
                timestamp = r[2],
                name      = r[3],
                known     = r[4],
            )
        )

    db.close()

    return hosts

def getLastestHosts():
    hosts = []

    db = sqlite3.connect(database_path)
    sql = "SELECT (mac, ipv4, timestamp, name, known) FROM HOST;"   # TODO: SELECT ROW WITH THE LATEST TIMESTAMP
    cur = db.cursor()
    cur.execute(sql)

    while True:
        records = cur.fetchall()

        for r in records:

            hosts.append(
                Host(
                    mac       = r[0],
                    ipv4      = r[1],
                    timestamp = r[2],
                    name      = r[3],
                    known     = r[4],
                )
            )

    db.close()

    return hosts

def insertOrUpdateHosts(hosts):
    """
    Create or update host table on database.

    :param hosts: Dictionary with Host objects
    :return:
    """

    # TODO: Validate MAC Address
    # TODO: Validate ipv4
    # TODO: Escape all fields
    # TODO: Convert known to boolean

    # INSERT new host or UPDATE ipv4 if already exists.
    sql = """
        INSERT INTO HOST (mac, ipv4, timestamp, name, known) VALUES (?,?,?,?,?)
            ON CONFLICT (mac) DO UPDATE SET ipv4=(?);
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    db = sqlite3.connect(database_path)
    for host in hosts:
        db.execute(
            sql,
            (host.mac, host.ipv4, timestamp, host.name, host.known, host.ipv4),
        )
    db.commit()
    db.close()

# ==============================================================================================