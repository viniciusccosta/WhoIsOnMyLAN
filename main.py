# ======================================================================================================================================
import xmltodict
import io
import json
import os
import argparse
import glob
import pexpect
import getpass

from bashcolors import bcolors as color
from pathlib    import Path
from datetime   import datetime


# ======================================================================================================================================
# GLOBAL
db_path     = "./database"
db_fullpath = f"{db_path}/wioml_db.json"

scan_path   = "./scans"

# ======================================================================================================================================
def runScan(cur_ip):
    # TODO: Validate user's input
    # TODO: Get automatically current IP

    """
        Method responsable for running a quick nmap scanning
    """

    scan_file_name = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")

    print(f"{color.BOLD}To perform a scan, it will be necessary to use the 'sudo' command. Please, enter your password...{color.ENDC}")
    child = pexpect.spawn(f'sudo nmap -sn -oX {scan_path}/{scan_file_name}.xml {cur_ip}')
    child.expect('password')

    pswd = getpass.getpass()
    child.sendline(pswd)

    # Read the output
    result = child.read()

def startupCheck():
    """
        Method responsable to verify everything before running the program.

        It will create all directories if they don't exist.
        It will create database it doens't exist.
        etc...
    """

    Path(db_path).mkdir(parents=True, exist_ok=True)
    Path(scan_path).mkdir(parents=True, exist_ok=True)

    # Checks if file exists
    if os.path.isfile(db_fullpath) and os.access(db_fullpath, os.R_OK):
        pass

    else:
        # Either file is missing or is not readable, creating file...
        with io.open(db_fullpath, 'w') as db_file:
            db_file.write(json.dumps({}))

def getOldHosts():
    """
    Method responsable to retrieve all hosts from database.

    :return: A dictionary with all hosts once founded.
    """

    oldhosts = {}

    with open(db_fullpath, "r") as ohf:
        try:
            oldhosts = json.loads(ohf.read())
        except json.decoder.JSONDecodeError as e:
            pass

        return oldhosts

def readLastScan(oldhosts):
    # TODO: oldhosts should be GLOBAL or at least a "db" object should be GLOBAL

    """
    Method responsable for:
        1) Interpret NMAP's XML
        2) Print a table showing all live hosts
        3) Return a dictionary with all live hosts.

    :param oldhosts: Dictionary return from "getOldHosts" method
    :return: a dictionary with all live hosts.
    """

    currenthosts = {}

    scans = glob.glob(f'{scan_path}/*.xml')
    if len(scans) < 1:
        raise FileNotFoundError

    last_scan = max(scans, key=os.path.getctime)

    with open(last_scan, "r") as f:
        d = xmltodict.parse(f.read())

        print(f"{color.BOLD}Comando:")
        print(f"{color.HEADER}\t{d['nmaprun']['@args']}{color.ENDC}\n")

        print(f"{color.BOLD}Hosts:{color.ENDC}")
        print(f"\t/{'-'*15}|{'-'*17}|{'-'*5}|{'-'*50}\\")
        print(f"\t|{color.BOLD}{'IP':^15}{color.ENDC}|{color.BOLD}{'MAC':^17}{color.ENDC}|{color.BOLD}{'KNOWN':^5}{color.ENDC}|{color.BOLD}{'NAME':^50.50}{color.ENDC}|")
        print(f"\t|{'-'*15}|{'-'*17}|{'-'*5}|{'-'*50}|")

        for h in d["nmaprun"]["host"]:
            try:
                ipv4    = h["address"][0]["@addr"]
                mac     = h["address"][1]["@addr"]
                known   = oldhosts.get(mac, {}).get("known", "N") == "Y"
                cor     = color.OKGREEN if known else color.FAIL
                known   = "✓" if known else "✗"
                name    = oldhosts.get(mac, {}).get("name", "")

                if mac in currenthosts:
                    print("MAC ADDRESS CLONED ?")

                currenthosts[mac] = {
                    "ipv4": ipv4,
                    "known": known,
                    "name": name,
                }

                print(f'\t|{cor}{ipv4:>15}{color.ENDC}|{cor}{mac:>17}{color.ENDC}|{cor}{known:^5}{color.ENDC}|{cor}{name:^50.50}{color.ENDC}|',)
            except Exception as e:
                pass

        print(f"\t\\{'-'*15}|{'-'*17}|{'-'*5}|{'-'*50}/")
        return currenthosts

def updateHosts(currenthosts):
    # TODO: Not good...

    """

    :param currenthosts:
    :return:
    """
    a = input(f"\n{color.BOLD}Modify database (Y/N):\n{color.ENDC}").strip().upper()
    while a not in ["Y","N"]:
        print(f"{color.FAIL}Invalid input...{color.ENDC}")
        a = input("\nModify database (Y/N):\n").strip().upper()

    if a == "Y":
        print()

        database_file = open(db_fullpath, "r")
        try:
            json_obj = json.load(database_file)
        except json.decoder.JSONDecodeError:
            json_obj = {}
        database_file.close()

        try:
            database_file = open(db_fullpath, "w+")

            for mac,host_info in currenthosts.items():

                known = ""
                name = ""

                # -----------------------
                # UPDATE
                if mac in json_obj:
                    print(f"\n{color.BOLD}{color.WARNING}Updating{color.ENDC}{color.BOLD} {mac} ({host_info['ipv4']}):{color.ENDC}")

                    input_known = input("Known [(Y)/(N)/blank to skip]?: ").strip().upper()
                    while input_known not in ["","Y","N"]:
                        print(f"{color.FAIL}Invalid input...{color.ENDC}")
                        input_known = input("Known [(Y)/(N)/blank to skip )?: ").strip().upper()
                    if input_known == "":
                        known = json_obj[mac]["known"]
                    else:
                        known = input_known

                    input_name = input(f"New name (- to clear): ").strip()
                    if input_name == "-":
                        name = ""
                    elif input_name != "":
                        name = input_name
                    else:
                        name = json_obj[mac]["name"]

                # -----------------------
                # CREATE
                else:
                    print(f"\n{color.BOLD}{color.OKBLUE}Adding{color.ENDC}{color.BOLD} {mac} ({host_info['ipv4']}) to the database:{color.ENDC}")

                    input_known = input("Known [(Y)/(N)]?: ").strip().upper()
                    while input_known not in ["","Y","N"]:
                        print(f"{color.FAIL}Invalid input...{color.ENDC}")
                        input_known = input("Known [(Y)/(N)]?: ").strip().upper()
                    if input_known == "":
                        known = "N"
                    else:
                        known = input_known

                    name = input("Name (or blank to skip): ").strip()

                # -----------------------

                json_obj[mac] = {'name': name, "known": known, 'ipv4': host_info["ipv4"]}

            json.dump(json_obj, database_file)

        except KeyboardInterrupt:
            json.dump(json_obj, database_file)
            database_file.close()

# ======================================================================================================================================
def main():
    parser = argparse.ArgumentParser(description="This program helps you to manager your network using NMAP",)
    parser.add_argument('-S', '--scan', help="Run a new scan and replace the old XML. Accept any string used on NMAP, such 192.168.0.0/24 or 192.168.0.*", type=str, required=False, default="")

    args = parser.parse_args()
    if args.scan != "":
        runScan(args.scan)

    startupCheck()
    database = getOldHosts()

    try:
        currenthosts = readLastScan(database)
    except FileNotFoundError as e:
        print("You need to run at least one scan first.")
        exit(1)

    updateHosts(currenthosts)

    print(f"\n{color.BOLD}Bye!{color.ENDC}")

# ======================================================================================================================================
if __name__ == "__main__":
    main()

# ======================================================================================================================================

# TODO: Use SQLITE instead of JSON
# TODO: Be able to retrieve database without a scanned XML
# TODO: Be able to edit database without a scanned XML
# TODO: GUI

# ======================================================================================================================================
# REFERENCES:

# https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python
# https://api.macvendors.com/28:83:35:EA:07:21
# https://stackoverflow.com/questions/11599263/making-it-pythonic-create-a-sqlite3-database-if-it-doesnt-exist#:~:text=3-,sqlite3.,connect%20using%20the%20sqlite3%20module.
# https://stackoverflow.com/questions/10607688/how-to-create-a-file-name-with-the-current-date-time-in-python

# ======================================================================================================================================