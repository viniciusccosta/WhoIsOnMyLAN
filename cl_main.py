# ======================================================================================================================================
import argparse

from pathlib    import Path

from database   import *
from nmap       import *
from host       import Host
from bashcolors import bcolors as bc

# ======================================================================================================================================
# GLOBAL
DB_PATH     = "./database"
DB_FILENAME = "wioml_db.sqlite3"
DB_FULLPATH = f"{DB_PATH}/{DB_FILENAME}"

SCAN_PATH   = "./scans"

# ======================================================================================================================================
# NMAP:
def runScan(target):
    quickScanToXml(target, SCAN_PATH)
    hosts = getHostsFromLastestScanXml(SCAN_PATH)
    insertOrUpdateHosts(hosts)
    # TODO: Retrieve lastest inserted/updated rows
    printHostTable(hosts)   # TODO: "Retrieve lastest inserted/updated rows" first

# ======================================================================================================================================
def startupCheck():
    """
        Method responsable to verify everything before running the program.

        It will create all directories if they don't exist.
        It will create database it doens't exist.
        etc...
    """

    # ------------------------------------------------
    # Creating directories:
    Path(DB_PATH).mkdir(parents=True, exist_ok=True)
    Path(SCAN_PATH).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------
    # Creating database:
    createDatabase(DB_FULLPATH)

    # ------------------------------------------------

def showMenu():
    menu = f"\n{bc.BOLD}"\
           f"(1) Scan\n"\
           f"(2) Show last scan\n"\
           f"(3) Show all hosts\n"\
           f"(4) Exit\n"\
           f"Choose an option: {bc.ENDC}"

    try:
        while True:
            # -----------------------------------------------------
            option = input(menu)
            while option not in [str(i) for i in range(1,5)]:
                print(f"{bc.FAIL}Invalid input...{bc.ENDC}")
                option = input(menu)

            print()

            # -----------------------------------------------------
            if option == "1":
                target = input(f"{bc.BOLD}Insert a IP and range:{bc.ENDC} ") # TODO: Validate
                runScan(target)

            # -----------------------------------------------------
            elif option == "2":
                try:
                    lastest_hosts = getHostsFromLastestScanXml(SCAN_PATH)
                    printHostTable(lastest_hosts)
                except FileNotFoundError:
                    print(f"{bc.FAIL}\nNo scan found\n{bc.ENDC}")

            # -----------------------------------------------------
            elif option == "3":
                printHostTable( getAllHosts() )

            # -----------------------------------------------------
            elif option == "4":
                raise KeyboardInterrupt

            # -----------------------------------------------------
    except KeyboardInterrupt:
        pass

def printHostTable(hosts):
    # --------------------------------------------------------------------------
    def horizontalDashedLine(begin="|", end="|"):
        print(f"\t{begin}", end="")
        for i,cw in enumerate(cols_wid):
            print(f"{'-'*cw}", end="|" if i < len(cols_wid) - 1 else f"{end}\n")

    # --------------------------------------------------------------------------
    def printRow(values, cor=bc.BOLD):
        print("\t", end="")
        for i,cw in enumerate(cols_wid):
            print(f"|{cor}{str(values[i]):^{cw}.{cw}}{bc.ENDC}", end="")
        print("|")

    # --------------------------------------------------------------------------
    cols_wid = [7,15,17,5,50]
    headers  = ["#","IP","MAC","KNOWN","NAME"]

    # --------------------------------------------------------------------------
    print(f"{bc.BOLD}Hosts:{bc.ENDC}")

    # --------------------------------------------------------------------------
    horizontalDashedLine(begin="/",end="\\")
    printRow(headers)
    horizontalDashedLine()

    # --------------------------------------------------------------------------
    for h,host in enumerate(hosts):
        if host.known:
            known_sym = "✓"
            cor       = bc.OKGREEN
        else:
            known_sym = "✗"
            cor       = bc.FAIL

        row = [h,host.ipv4,host.mac,known_sym,host.name]
        printRow(values=row,cor=cor)

    # --------------------------------------------------------------------------
    horizontalDashedLine(begin="\\",end="/")

# ======================================================================================================================================
def main():
    # -----------------------------------
    startupCheck()

    # -----------------------------------
    # Command Line Arguments:
    parser = argparse.ArgumentParser(description="This program helps you to manager your network using NMAP",)
    parser.add_argument('-S', '--scan', help="Run a new scan and replace the old XML. Accept any string used on NMAP, such 192.168.0.0/24 or 192.168.0.*", type=str, required=False, default="")
    args = parser.parse_args()

    if args.scan != "":
        runScan(args.scan)

    # -----------------------------------
    else:
        showMenu()

    # -----------------------------------
    print(f"\n{bc.BOLD}Bye!{bc.ENDC}")

if __name__ == "__main__":
    main()

# ======================================================================================================================================

# TODO: Do a GUI version

# ======================================================================================================================================
# REFERENCES:

# https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python
# https://api.macvendors.com/28:83:35:EA:07:21
# https://stackoverflow.com/questions/11599263/making-it-pythonic-create-a-sqlite3-database-if-it-doesnt-exist#:~:text=3-,sqlite3.,connect%20using%20the%20sqlite3%20module.
# https://stackoverflow.com/questions/10607688/how-to-create-a-file-name-with-the-current-date-time-in-python

# ======================================================================================================================================