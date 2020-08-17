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

def getConn():
    conn = sqlite3.connect(database_path)
    conn.enable_load_extension(True)
    conn.load_extension("./inet.so")

    return conn

# ==============================================================================================
# TABLE HOST:
from host import Host

def getAllHosts():
    """
    Method responsable to retrieve all hosts from database.

    :return: A dictionary with all hosts once founded.
    """

    hosts = []

    conn = getConn()
    sql = "SELECT mac, ipv4, timestamp, name, known FROM HOST ORDER BY INET_ATON(ipv4);"
    cur = conn.cursor()
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

    conn.close()

    return hosts

def getLastestHosts():
    hosts = []

    conn = getConn()
    sql = """
            SELECT
                a.mac,
                a.ipv4,
                a.timestamp,
                a.name,
                a.known
                
                FROM 
                    HOST a
                INNER JOIN ( SELECT MAX(host.timestamp) ts FROM HOST ORDER BY host.timestamp DESC LIMIT 1 ) b
                    ON a.timestamp = b.ts
                
                ORDER BY 
                    INET_ATON(a.ipv4) ASC;
    """
    cur = conn.cursor()
    cur.execute(sql)

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

    conn.close()

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
            ON CONFLICT (mac) DO UPDATE SET ipv4=(?), timestamp=(?);
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    db = sqlite3.connect(database_path)
    for host in hosts:
        db.execute(
            sql,
            (host.mac, host.ipv4, timestamp, host.name, host.known, host.ipv4, timestamp),
        )
    db.commit()
    db.close()

def getHosts(hosts):
    conn = getConn()

    for i,host in enumerate(hosts):
        sql = "SELECT mac, ipv4, timestamp, name, known FROM HOST WHERE mac=(?);"
        cur = conn.cursor()
        cur.execute(sql,(host.mac,))

        db_res = cur.fetchone()
        host.name  = db_res[3]
        host.known = db_res[4]

    conn.close()
    return hosts

# ==============================================================================================