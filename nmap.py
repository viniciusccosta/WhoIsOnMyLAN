# ==============================================================================
from datetime import datetime
import time
from bashcolors import bcolors as color
import pexpect
import getpass
import os
import xmltodict
import glob

from host import Host

# ==============================================================================
def quickScanToXml(target, file_path, filename=datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")):
    """
    This method will run a quick scan using nmap.
    "sudo nmap -sn -oX FILE_FULL_PATH.xml aaa.bbb.ccc.ddd/ee"

    :param target: NMAP's target
    :param file_path: Where XML is going to be stored
    :param filename: XML file's name
    :return: Whatever "child.read()" returns
    """

    # TODO: Validate target
    # TODO: Automatically get the current IP and the current mask

    """
        Method responsable for running a quick nmap scanning
    """

    print(f"{color.BOLD}To perform a scan, it will be necessary to use the 'sudo' command. Please, enter your password...{color.ENDC}")
    child = pexpect.spawn(f'sudo nmap -sn -oX {file_path}/{filename}.xml {target}')
    child.expect('password')

    pswd = getpass.getpass()
    child.sendline(pswd)

    # Read the output
    result = child.read()

    return result

# ==============================================================================
def getHostsFromLastestScanXml(scan_path):
    # ----------------------------------------------------------
    # Try to open last XML:
    scans = glob.glob(f'{scan_path}/*.xml')
    if len(scans) < 1:
        raise FileNotFoundError

    # ----------------------------------------------------------
    hosts     = []
    last_scan = max(scans, key=os.path.getctime)

    with open(last_scan, "r") as f:
        d         = xmltodict.parse(f.read())

        epoch     = int(d["nmaprun"]["@start"])                                 # Convert to int ?
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))

        for h in d["nmaprun"]["host"]:
            try:
                ipv4        = h["address"][0]["@addr"]
                mac         = h["address"][1]["@addr"]

                hosts.append( Host(mac, ipv4, timestamp) )
            except KeyError as e:
                # It will always raise an KeyError for own IP.
                pass

    return hosts
    # ----------------------------------------------------------

# ==============================================================================